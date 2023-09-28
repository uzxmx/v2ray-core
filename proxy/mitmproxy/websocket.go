package mitmproxy

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

var (
	DefaultWSUpgrader = &websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		// Only the targetConn choose to CheckOrigin or not
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	DefaultWSDialer = &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}, //nolint: gosec //ok
	}
)

type Direction int32

const (
	Inbound Direction = iota
	Outbound
)

func (d Direction) String() string {
	switch d {
	case Inbound:
		return "Inbound"
	case Outbound:
		return "Outbound"
	default:
		return ""
	}
}

type WSMessage struct {
	direction Direction
	Type      int
	Msg       []byte
}

func (m *WSMessage) Direction() Direction {
	return m.direction
}

func (p *Proxy) serveWS(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	outreq := req.Clone(ctx)

	if req.ContentLength == 0 {
		outreq.Body = nil
	}

	if outreq.Body != nil {
		// Reading from the request body after returning from a handler is not
		// allowed, and the RoundTrip goroutine that reads the Body can outlive
		// this handler. This can lead to a crash if the handler panics (see
		// Issue 46866). Although calling Close doesn't guarantee there isn't
		// any Read in flight after the handle returns, in practice it's safe to
		// read after closing it.
		defer outreq.Body.Close()
	}

	if outreq.Header == nil {
		outreq.Header = make(http.Header) // Issue 33142: historical behavior was to always allocate
	}

	if req.URL.Scheme == "" {
		outreq.URL.Host = outreq.Host
		outreq.URL.Scheme = "wss"
	}

	if p.director != nil {
		p.director(outreq)
	}

	outreq.Close = false

	removeConnectionHeaders(outreq.Header)

	// Remove hop-by-hop headers to the backend. Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.
	for _, h := range hopHeaders {
		outreq.Header.Del(h)
	}

	// Remove duplicatet websocket header
	outreq.Header.Del("Sec-Websocket-Version")
	outreq.Header.Del("Sec-Websocket-Key")

	backConn, res, err := p.wsDialer.DialContext(ctx, outreq.URL.String(), outreq.Header)
	if err != nil {
		log.Printf("Cannot dial to remote backend url %s", err)

		if res != nil {
			// If the WebSocket handshake fails, ErrBadHandshake is returned
			// along with a non-nil *http.Response so that callers can handle
			// redirects, authentication, etcetera.
			if err = p.copyResponse(rw, res.Body, p.getFlushInterval(res)); err != nil {
				log.Printf("Cannot write response after failed remote backend handshake: %s", err)
			}
		} else {
			p.errorHandler(rw, req, err)
		}

		return
	}

	backConnCloseCh := make(chan bool)

	go func() {
		// Ensure that the cancellation of a request closes the backend.
		select {
		case <-req.Context().Done():
		case <-backConnCloseCh:
		}
		backConn.Close()
	}()

	defer close(backConnCloseCh)

	// Only pass those headers to the upgrader.
	upgradeHeader := http.Header{}
	if hdr := res.Header.Get("Sec-Websocket-Protocol"); hdr != "" {
		upgradeHeader.Set("Sec-Websocket-Protocol", hdr)
	}

	if hdr := res.Header.Get("Set-Cookie"); hdr != "" {
		upgradeHeader.Set("Set-Cookie", hdr)
	}

	// Now upgrade the existing incoming request to a WebSocket connection.
	// Also pass the header that we gathered from the Dial handshake.
	// If the upgrade fails, then Upgrade replies to the client with an HTTP error
	// response.
	conn, err := p.wsUpgrader.Upgrade(rw, req, upgradeHeader)
	if err != nil {
		p.logErrorf("Cannot upgrade %s", err)
		return
	}
	defer conn.Close()

	errClient := make(chan error, 1)
	errBackend := make(chan error, 1)

	replicator := &websocketReplicator{modifier: p.wsMessageMofifier}

	go replicator.copy(backConn, conn, Outbound, errBackend)
	go replicator.copy(conn, backConn, Inbound, errClient)

	var message string
	select {
	case err = <-errClient:
		message = "Error when copying from backend to client: %v"
	case err = <-errBackend:
		message = "Error when copying from client to backend: %v"
	}

	if e, ok := err.(*websocket.CloseError); !ok || e.Code == websocket.CloseAbnormalClosure {
		p.logErrorf(message, err)
	}
}

type websocketReplicator struct {
	modifier WSMessageModifierFunc
}

func (r *websocketReplicator) copy(dst, src *websocket.Conn, direction Direction, errc chan error) {
	src.SetPingHandler(func(data string) error {
		return dst.WriteControl(websocket.PingMessage, []byte(data), time.Time{})
	})

	src.SetPongHandler(func(data string) error {
		return dst.WriteControl(websocket.PongMessage, []byte(data), time.Time{})
	})

	for {
		msgType, msg, rerr := src.ReadMessage()
		if rerr != nil {
			m := websocket.FormatCloseMessage(websocket.CloseNormalClosure, fmt.Sprintf("%v", rerr))

			if e, ok := rerr.(*websocket.CloseError); ok {
				// Following codes are not valid on the wire so just close the
				// underlying TCP connection without sending a close frame.
				if e.Code == websocket.CloseAbnormalClosure || e.Code == websocket.CloseTLSHandshake {
					errc <- rerr
					return
				}

				if e.Code != websocket.CloseNoStatusReceived {
					m = websocket.FormatCloseMessage(e.Code, e.Text)
				}
			}
			errc <- rerr

			_ = dst.WriteMessage(websocket.CloseMessage, m)

			return
		}

		wsMSg := &WSMessage{Type: msgType, Msg: msg, direction: direction}
		if r.modifier != nil {
			r.modifier(wsMSg)
		}

		if werr := dst.WriteMessage(wsMSg.Type, wsMSg.Msg); werr != nil {
			errc <- werr
			return
		}
	}
}
