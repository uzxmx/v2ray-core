package mitmproxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hupe1980/golog"
	"golang.org/x/net/http/httpguts"
)

type RequestModifierFunc func(req *http.Request)

type ResponseModifierFunc func(res *http.Response) error

type WSMessageModifierFunc func(msg *WSMessage)

type ErrorHandlerFunc func(http.ResponseWriter, *http.Request, error)

// BufferPool is an interface for getting and returning temporary
// byte slices for use by io.CopyBuffer.
type BufferPool interface {
	Get() []byte
	Put([]byte)
}

type Options struct {
	// MITM Config
	MITMConfig *MITMConfig

	// The transport used to perform proxy requests.
	// If nil, DefaultTransport is used.
	Transport http.RoundTripper

	// The upgrader used to upgrade a HTTP connection
	// to a WebSocket connection.
	// If nil, DefaultWSUpgrader is used.
	WSUpgrader *websocket.Upgrader

	// The dialer used to connect to a WebSocket server.
	// If nil, DefaultWSDialer is used.
	WSDialer *websocket.Dialer

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	// A negative value means to flush immediately
	// after each write to the client.
	// The FlushInterval is ignored when Proxy
	// recognizes a response as a streaming response, or
	// if its ContentLength is -1; for such responses, writes
	// are flushed to the client immediately.
	FlushInterval time.Duration

	// Logger specifies an optional logger.
	// If nil, logging is done via the log package's standard logger.
	Logger golog.Logger

	// BufferPool optionally specifies a buffer pool to
	// get byte slices for use by io.CopyBuffer when
	// copying HTTP response bodies.
	BufferPool BufferPool

	// ErrorHandler is an optional function that handles errors
	// reaching the backend or errors from responseModifier specified in
	// OnResponse.
	//
	// If nil, the default is to log the provided error and return
	// a 502 Status Bad Gateway response.
	ErrorHandler ErrorHandlerFunc
}

type Proxy struct {
	*logger
	mitmCfg           *MITMConfig
	transport         http.RoundTripper
	wsUpgrader        *websocket.Upgrader
	wsDialer          *websocket.Dialer
	flushInterval     time.Duration
	bufferPool        BufferPool
	director          RequestModifierFunc
	responseModifier  ResponseModifierFunc
	errorHandler      ErrorHandlerFunc
	wsMessageMofifier WSMessageModifierFunc
}

func New(optFns ...func(*Options)) (*Proxy, error) {
	options := Options{
		Logger:     golog.NewGoLogger(golog.INFO, log.Default()),
		Transport:  DefaultTransport,
		WSUpgrader: DefaultWSUpgrader,
		WSDialer:   DefaultWSDialer,
	}

	for _, fn := range optFns {
		fn(&options)
	}

	if options.ErrorHandler == nil {
		options.ErrorHandler = func(rw http.ResponseWriter, r *http.Request, err error) {
			options.Logger.Printf(golog.ERROR, "proxy error: %v", err)
			http.Error(rw, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		}
	}

	if options.MITMConfig == nil {
		mitmCfg, err := NewMITMConfig(func(m *MITMOptions) {
			m.Logger = options.Logger
		})
		if err != nil {
			return nil, err
		}

		options.MITMConfig = mitmCfg
	}

	return &Proxy{
		logger:        &logger{options.Logger},
		mitmCfg:       options.MITMConfig,
		transport:     options.Transport,
		flushInterval: options.FlushInterval,
		bufferPool:    options.BufferPool,
		wsUpgrader:    options.WSUpgrader,
		wsDialer:      options.WSDialer,
		errorHandler:  options.ErrorHandler,
	}, nil
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		p.handleConnect(rw, req)
		return
	}

	p.logDebugf("Got request %s %s %s %s", req.URL.Path, req.Host, req.Method, req.URL)

	reqUpType := upgradeType(req.Header)
	if reqUpType != "" {
		switch reqUpType {
		case "websocket":
			p.serveWS(rw, req)
			return
		default:
			p.errorHandler(rw, req, fmt.Errorf("unsupported upgrade type: %s", reqUpType))
			return
		}
	}

	p.serveHTTP(rw, req)
}

func (p *Proxy) OnRequest(fn RequestModifierFunc) {
	p.director = fn
}

func (p *Proxy) OnResponse(fn ResponseModifierFunc) {
	p.responseModifier = fn
}

func (p *Proxy) OnWSMessage(fn WSMessageModifierFunc) {
	p.wsMessageMofifier = fn
}

// func (p *Proxy) logf(level golog.Level, format string, args ...interface{}) {
// 	p.logger.Printf(level, format, args...)
// }

// func (p *Proxy) logDebugf(format string, args ...interface{}) {
// 	p.logf(golog.DEBUG, format, args...)
// }

// func (p *Proxy) logErrorf(format string, args ...interface{}) {
// 	p.logf(golog.ERROR, format, args...)
// }

// modifyResponse conditionally runs the optional ModifyResponse hook
// and reports whether the request should proceed.
func (p *Proxy) modifyResponse(rw http.ResponseWriter, res *http.Response, req *http.Request) bool {
	if p.responseModifier == nil {
		return true
	}

	if err := p.responseModifier(res); err != nil {
		res.Body.Close()
		p.errorHandler(rw, req, err)

		return false
	}

	return true
}

// getFlushInterval returns the p.FlushInterval value, conditionally
// overriding its value for a specific request/response.
func (p *Proxy) getFlushInterval(res *http.Response) time.Duration {
	resCT := res.Header.Get("Content-Type")

	// For Server-Sent Events responses, flush immediately.
	// The MIME type is defined in https://www.w3.org/TR/eventsource/#text-event-stream
	if resCT == "text/event-stream" {
		return -1 // negative means immediately
	}

	// We might have the case of streaming for which Content-Length might be unset.
	if res.ContentLength == -1 {
		return -1
	}

	return p.flushInterval
}

func (p *Proxy) copyResponse(dst io.Writer, src io.Reader, flushInterval time.Duration) error {
	if flushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: flushInterval,
			}
			defer mlw.stop()

			// set up initial timer so headers get flushed even if body writes are delayed
			mlw.flushPending = true
			mlw.t = time.AfterFunc(flushInterval, mlw.delayedFlush)

			dst = mlw
		}
	}

	var buf []byte
	if p.bufferPool != nil {
		buf = p.bufferPool.Get()
		defer p.bufferPool.Put(buf)
	}

	_, err := p.copyBuffer(dst, src, buf)

	return err
}

// copyBuffer returns any write errors or non-EOF read errors, and the amount
// of bytes written.
func (p *Proxy) copyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}

	var written int64

	for {
		nr, rerr := src.Read(buf)
		if rerr != nil && rerr != io.EOF && rerr != context.Canceled {
			p.logErrorf("Proxy read error during body copy: %v", rerr)
		}

		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}

			if werr != nil {
				return written, werr
			}

			if nr != nw {
				return written, io.ErrShortWrite
			}
		}

		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}

			return written, rerr
		}
	}
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration // non-zero; negative means to flush immediately

	mu           sync.Mutex // protects t, flushPending, and dst.Flush
	t            *time.Timer
	flushPending bool
}

func (m *maxLatencyWriter) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	n, err = m.dst.Write(p)

	if m.latency < 0 {
		m.dst.Flush()
		return
	}

	if m.flushPending {
		return
	}

	if m.t == nil {
		m.t = time.AfterFunc(m.latency, m.delayedFlush)
	} else {
		m.t.Reset(m.latency)
	}

	m.flushPending = true

	return
}

func (m *maxLatencyWriter) delayedFlush() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.flushPending { // if stop was called but AfterFunc already started this goroutine
		return
	}

	m.dst.Flush()

	m.flushPending = false
}

func (m *maxLatencyWriter) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.flushPending = false

	if m.t != nil {
		m.t.Stop()
	}
}

// Hop-by-hop headers. These are removed when sent to the backend.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

// removeConnectionHeaders removes hop-by-hop headers listed in the "Connection" header of h.
// See RFC 7230, section 6.1
func removeConnectionHeaders(h http.Header) {
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}

	return h.Get("Upgrade")
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
