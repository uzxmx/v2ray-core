package mitmproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
)

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logErrorf("ResponseWriter is not a http.Hijacker (type: %T)", w)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)

		return
	}

	w.WriteHeader(http.StatusOK)

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.logErrorf("Hijacking client connection failed: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)

		return
	}
	defer clientConn.Close()

	clientConn, err = p.clientTLSConn(clientConn, p.mitmCfg.NewTLSConfigForHost(r.URL.Hostname()))
	if err != nil {
		p.logErrorf("Securing client connection failed: %v", err)
		return
	}

	clientConnNotify := ConnNotify{clientConn, make(chan struct{})}
	l := &onceAcceptListener{clientConnNotify.Conn}

	err = http.Serve(l, p)
	if err != nil && !errors.Is(err, errAlreadyAccepted) {
		p.logErrorf("Serving HTTP request failed: %v", err)
	}

	<-clientConnNotify.closed
}

func (p *Proxy) clientTLSConn(conn net.Conn, config *tls.Config) (*tls.Conn, error) {
	tlsConn := tls.Server(conn, config)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("handshake error: %w", err)
	}

	return tlsConn, nil
}

var errAlreadyAccepted = errors.New("listener already accepted")

// onceAcceptListener implements net.Listener.
//
// Accepts a connection once and returns an error on subsequent
// attempts.
type onceAcceptListener struct {
	c net.Conn
}

func (l *onceAcceptListener) Accept() (net.Conn, error) {
	if l.c == nil {
		return nil, errAlreadyAccepted
	}

	c := l.c
	l.c = nil

	return c, nil
}

func (l *onceAcceptListener) Close() error {
	return nil
}

func (l *onceAcceptListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

// ConnNotify embeds net.Conn and adds a channel field for notifying
// that the connection was closed.
type ConnNotify struct {
	net.Conn
	closed chan struct{}
}

func (c *ConnNotify) Close() {
	c.Conn.Close()
	c.closed <- struct{}{}
}
