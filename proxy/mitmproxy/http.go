package mitmproxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
)

var (
	DefaultTransport = newDefaultTransport()
)

func (p *Proxy) serveHTTP(rw http.ResponseWriter, req *http.Request) {
	fmt.Println("------ serveHTTP ------------")
	ctx := req.Context()

	outreq := req.Clone(ctx)

	if req.ContentLength == 0 {
		outreq.Body = nil
	}

	if outreq.Body != nil {
		// Reading from the request body after returning from a handler is not
		// allowed, and the RoundTrip goroutine that reads the Body can outlive
		// this handler. This can lead to a crash if the handler panics.
		// Although calling Close doesn't guarantee there isn't any Read in
		// flight after the handle returns, in practice it's safe to read after
		// closing it.
		defer outreq.Body.Close()
	}

	if outreq.Header == nil {
		outreq.Header = make(http.Header)
	}

	if outreq.URL.Scheme == "" {
		outreq.URL.Host = outreq.Host
		outreq.URL.Scheme = "https"
	}

	if p.director != nil {
		p.director(outreq)
	}

	outreq.Close = false

	// If User-Agent is not set by client, then explicitly
	// disable it so it's not set to default value by std lib
	if _, ok := outreq.Header["User-Agent"]; !ok {
		outreq.Header.Set("User-Agent", "")
	}

	removeConnectionHeaders(outreq.Header)

	// Remove hop-by-hop headers to the backend. Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.
	for _, h := range hopHeaders {
		outreq.Header.Del(h)
	}

	// Tell backend applications that care about trailer support
	// that we support trailers. (We do, but we don't go out of our way to
	// advertise that unless the incoming client request thought it was worth
	// mentioning.) Note that we look at req.Header, not outreq.Header, since
	// the latter has passed through removeConnectionHeaders.
	if httpguts.HeaderValuesContainsToken(req.Header["Te"], "trailers") {
		outreq.Header.Set("Te", "trailers")
	}

	res, err := p.transport.RoundTrip(outreq)
	if err != nil {
		p.errorHandler(rw, outreq, err)
		return
	}

	removeConnectionHeaders(res.Header)

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	if !p.modifyResponse(rw, res, outreq) {
		return
	}

	copyHeader(rw.Header(), res.Header)

	// The "Trailer" header isn't included in the Transport's response,
	// at least for *http.Transport. Build it up from Trailer.
	announcedTrailers := len(res.Trailer)
	if announcedTrailers > 0 {
		trailerKeys := make([]string, 0, len(res.Trailer))
		for k := range res.Trailer {
			trailerKeys = append(trailerKeys, k)
		}

		rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	rw.WriteHeader(res.StatusCode)

	err = p.copyResponse(rw, res.Body, p.getFlushInterval(res))
	if err != nil {
		defer res.Body.Close()
		// Since we're streaming the response, if we run into an error all we can do
		// is abort the request.
		panic(http.ErrAbortHandler)
	}

	res.Body.Close() // close now, instead of defer, to populate res.Trailer

	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		if fl, ok := rw.(http.Flusher); ok {
			fl.Flush()
		}
	}

	if len(res.Trailer) == announcedTrailers {
		copyHeader(rw.Header(), res.Trailer)
		return
	}

	for k, vv := range res.Trailer {
		k = http.TrailerPrefix + k
		for _, v := range vv {
			rw.Header().Add(k, v)
		}
	}
}

func newDefaultTransport() http.RoundTripper {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint: gosec //ok
	//transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)

	return transport
}
