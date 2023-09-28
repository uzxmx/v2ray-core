package shadowsocks

import (
	"context"
	gotls "crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/cryptobyte"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/log"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/net/packetaddr"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/common/protocol/tls"
	udp_proto "github.com/v2fly/v2ray-core/v5/common/protocol/udp"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/common/signal"
	"github.com/v2fly/v2ray-core/v5/common/task"
	"github.com/v2fly/v2ray-core/v5/features/policy"
	"github.com/v2fly/v2ray-core/v5/features/routing"
	"github.com/v2fly/v2ray-core/v5/proxy/mitmproxy"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/udp"
)

type cachedReader struct {
	sync.Mutex
	reader buf.Reader
	cache  buf.MultiBuffer
}

func (r *cachedReader) Cache(b *buf.Buffer) {
	mb, _ := r.reader.ReadMultiBuffer()
	r.Lock()
	if !mb.IsEmpty() {
		r.cache, _ = buf.MergeMulti(r.cache, mb)
	}
	b.Clear()
	rawBytes := b.Extend(buf.Size)
	n := r.cache.Copy(rawBytes)
	b.Resize(0, int32(n))
	r.Unlock()
}

func (r *cachedReader) readInternal() buf.MultiBuffer {
	r.Lock()
	defer r.Unlock()

	if r.cache != nil && !r.cache.IsEmpty() {
		mb := r.cache
		r.cache = nil
		return mb
	}

	return nil
}

func (r *cachedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBuffer()
}

// func (r *cachedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
// 	mb := r.readInternal()
// 	if mb != nil {
// 		return mb, nil
// 	}
//
// 	return r.reader.ReadMultiBufferTimeout(timeout)
// }

// func (r *cachedReader) Interrupt() {
// 	r.Lock()
// 	if r.cache != nil {
// 		r.cache = buf.ReleaseMulti(r.cache)
// 	}
// 	r.Unlock()
// 	r.reader.Interrupt()
// }

var dumper *Dumper
var mitmCfg *mitmproxy.MITMConfig
var mproxy *mitmproxy.Proxy

func init() {
	ca, privateKey, err := mitmproxy.LoadOrCreateCA("/Users/xmx/.mitmproxy/mitmproxy-ca-cert.pem", "/Users/xmx/.mitmproxy/mitmproxy-ca.pem", func(c *mitmproxy.CAOptions) {
		c.Validity = 365 * 24 * time.Hour
	})
	if err != nil {
		panic(err)
	}

	mitmCfg, err = mitmproxy.NewMITMConfig(func(m *mitmproxy.MITMOptions) {
		m.CA = ca
		m.PrivateKey = privateKey
	})
	if err != nil {
		panic(err)
	}

	mproxy, err = mitmproxy.New(func(o *mitmproxy.Options) {
		// o.Logger = golog.NewGoLogger(golog.DEBUG, log.Default())
		o.MITMConfig = mitmCfg
	})
	if err != nil {
		panic(err)
	}

	dumper = newDumper()
	go dumper.run()
}

type Dumper struct {
	nextId int
	ch     chan *Packet
	file   *os.File
}

func newDumper() *Dumper {
	file, err := os.OpenFile("data.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	return &Dumper{
		nextId: 1,
		ch:     make(chan *Packet, 10),
		file:   file,
	}
}

func (d *Dumper) run() {
	ticker := time.NewTicker(1000 * time.Millisecond)
	for {
		select {
		case <-ticker.C:
		case packet := <-d.ch:
			id := packet.conn.id

			var builder cryptobyte.Builder
			builder.AddUint32(uint32(id))
			builder.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(packet.conn.dest.String()))
			})
			if packet.upload {
				builder.AddUint8(1)
			} else {
				builder.AddUint8(0)
			}
			if packet.raw {
				builder.AddUint8(1)
			} else {
				builder.AddUint8(0)
			}
			builder.AddUint64(uint64(packet.time.UnixMilli()))
			builder.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(packet.payload)
			})

			data, err := builder.Bytes()
			if err != nil {
				panic(err)
			}
			d.file.Write(data)
			d.file.Sync()
		}
	}
}

func (d *Dumper) queuePacket(packet *Packet) {
	d.ch <- packet
}

func (d *Dumper) getNextId() int {
	id := d.nextId
	d.nextId++
	return id
}

type Packet struct {
	conn    *ConnInterceptor
	time    time.Time
	payload []byte
	upload  bool
	raw     bool
}

type ConnInterceptor struct {
	id     int
	reader buf.Reader
	writer buf.Writer
	dest   net.Destination

	reqDone  bool
	respDone bool
}

func newConnInterceptor(dest net.Destination) *ConnInterceptor {
	return &ConnInterceptor{id: dumper.getNextId(), dest: dest}
}

func (d *ConnInterceptor) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffer, err := d.reader.ReadMultiBuffer()
	if err == nil && buffer.Len() > 0 {
		payload := make([]byte, buffer.Len())
		buffer.Copy(payload)
		dumper.queuePacket(&Packet{
			conn:    d,
			time:    time.Now(),
			payload: payload,
			upload:  true,
			raw:     true,
		})
	}
	return buffer, err
}

func (d *ConnInterceptor) WriteMultiBuffer(mb buf.MultiBuffer) error {
	payload := make([]byte, mb.Len())
	mb.Copy(payload)
	dumper.queuePacket(&Packet{
		conn:    d,
		time:    time.Now(),
		payload: payload,
		upload:  false,
		raw:     true,
	})
	return d.writer.WriteMultiBuffer(mb)
}

type Server struct {
	config        *ServerConfig
	user          *protocol.MemoryUser
	policyManager policy.Manager
}

// NewServer create a new Shadowsocks server.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	if config.GetUser() == nil {
		return nil, newError("user is not specified")
	}

	mUser, err := config.User.ToMemoryUser()
	if err != nil {
		return nil, newError("failed to parse user account").Base(err)
	}

	v := core.MustFromContext(ctx)
	s := &Server{
		config:        config,
		user:          mUser,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	return s, nil
}

func (s *Server) Network() []net.Network {
	list := s.config.Network
	if len(list) == 0 {
		list = append(list, net.Network_TCP)
	}
	if s.config.UdpEnabled {
		list = append(list, net.Network_UDP)
	}
	return list
}

func (s *Server) Process(ctx context.Context, network net.Network, conn internet.Connection, dispatcher routing.Dispatcher) error {
	switch network {
	case net.Network_TCP:
		return s.handleConnection(ctx, conn, dispatcher)
	case net.Network_UDP:
		return s.handlerUDPPayload(ctx, conn, dispatcher)
	default:
		return newError("unknown network: ", network)
	}
}

func (s *Server) handlerUDPPayload(ctx context.Context, conn internet.Connection, dispatcher routing.Dispatcher) error {
	udpDispatcherConstructor := udp.NewSplitDispatcher
	switch s.config.PacketEncoding {
	case packetaddr.PacketAddrType_None:
		break
	case packetaddr.PacketAddrType_Packet:
		packetAddrDispatcherFactory := udp.NewPacketAddrDispatcherCreator(ctx)
		udpDispatcherConstructor = packetAddrDispatcherFactory.NewPacketAddrDispatcher
	}

	udpServer := udpDispatcherConstructor(dispatcher, func(ctx context.Context, packet *udp_proto.Packet) {
		request := protocol.RequestHeaderFromContext(ctx)
		if request == nil {
			request = &protocol.RequestHeader{
				Port:    packet.Source.Port,
				Address: packet.Source.Address,
				User:    s.user,
			}
		}

		payload := packet.Payload
		data, err := EncodeUDPPacket(request, payload.Bytes())
		payload.Release()
		if err != nil {
			newError("failed to encode UDP packet").Base(err).AtWarning().WriteToLog(session.ExportIDToError(ctx))
			return
		}
		defer data.Release()

		conn.Write(data.Bytes())
	})

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}
	inbound.User = s.user

	reader := buf.NewPacketReader(conn)
	for {
		mpayload, err := reader.ReadMultiBuffer()
		if err != nil {
			break
		}

		for _, payload := range mpayload {
			request, data, err := DecodeUDPPacket(s.user, payload)
			if err != nil {
				if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Source.IsValid() {
					newError("dropping invalid UDP packet from: ", inbound.Source).Base(err).WriteToLog(session.ExportIDToError(ctx))
					log.Record(&log.AccessMessage{
						From:   inbound.Source,
						To:     "",
						Status: log.AccessRejected,
						Reason: err,
					})
				}
				payload.Release()
				continue
			}

			currentPacketCtx := ctx
			dest := request.Destination()
			if inbound.Source.IsValid() {
				currentPacketCtx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
					From:   inbound.Source,
					To:     dest,
					Status: log.AccessAccepted,
					Reason: "",
					Email:  request.User.Email,
				})
			}
			newError("tunnelling request to ", dest).WriteToLog(session.ExportIDToError(currentPacketCtx))

			currentPacketCtx = protocol.ContextWithRequestHeader(currentPacketCtx, request)
			udpServer.Dispatch(currentPacketCtx, dest, data)
		}
	}

	return nil
}

func (s *Server) handleConnection(ctx context.Context, conn internet.Connection, dispatcher routing.Dispatcher) error {
	sessionPolicy := s.policyManager.ForLevel(s.user.Level)
	conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake))

	bufferedReader := buf.BufferedReader{Reader: buf.NewReader(conn)}
	request, bodyReader, err := ReadTCPSession(s.user, &bufferedReader)
	if err != nil {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: err,
		})
		return newError("failed to create request from: ", conn.RemoteAddr()).Base(err)
	}
	conn.SetReadDeadline(time.Time{})

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}
	inbound.User = s.user

	dest := request.Destination()
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  request.User.Email,
	})
	newError("111 tunnelling request to ", dest).WriteToLog(session.ExportIDToError(ctx))

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)
	// TODO
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	connInterceptor := newConnInterceptor(dest)

	r := &cachedReader{reader: bodyReader}
	connInterceptor.reader = r

	bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
	responseWriter, err := WriteTCPResponse(request, bufferedWriter)
	if err != nil {
		return newError("failed to write response").Base(err)
	}

	connInterceptor.writer = responseWriter

	if false && sniffer(ctx, r) {
		c := &wrappedConn{
			reader: connInterceptor,
			writer: connInterceptor,
			conn:   conn,
		}

		bufferedWriter.SetBuffered(false)

		tlsConn := gotls.Server(c, mitmCfg.NewTLSConfigForHost(dest.Address.Domain()))
		if err := tlsConn.Handshake(); err != nil {
			tlsConn.Close()
			return fmt.Errorf("handshake error: %w", err)
		}
		newError("TLS handshake ok -------------------------").WriteToLog()

		clientConnNotify := ConnNotify{&wrappedTLSConn{
			connInterceptor: connInterceptor,
			conn:            tlsConn,
		}, make(chan struct{})}
		l := &onceAcceptListener{clientConnNotify.Conn}

		err = http.Serve(l, mproxy)
		if err != nil && !errors.Is(err, errAlreadyAccepted) {
			newError("Serving HTTP request failed", err).WriteToLog()
		}

		<-clientConnNotify.closed
	} else {
		responseDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

			{
				payload, err := link.Reader.ReadMultiBuffer()
				if err != nil {
					return err
				}
				if err := connInterceptor.WriteMultiBuffer(payload); err != nil {
					return err
				}
			}

			if err := bufferedWriter.SetBuffered(false); err != nil {
				return err
			}

			if err := buf.Copy(link.Reader, connInterceptor, buf.UpdateActivity(timer)); err != nil {
				return newError("failed to transport all TCP response").Base(err)
			}

			return nil
		}

		requestDone := func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

			if err := buf.Copy(connInterceptor, link.Writer, buf.UpdateActivity(timer)); err != nil {
				return newError("failed to transport all TCP request").Base(err)
			}

			return nil
		}

		requestDoneAndCloseWriter := task.OnSuccess(requestDone, task.Close(link.Writer))
		if err := task.Run(ctx, requestDoneAndCloseWriter, responseDone); err != nil {
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
			return newError("connection ends").Base(err)
		}
	}

	return nil
}

func sniffer(ctx context.Context, cReader *cachedReader) bool {
	payload := buf.New()
	defer payload.Release()

	totalAttempt := 0
	for {
		select {
		case <-ctx.Done():
			// return nil, ctx.Err()
			return false
		default:
			totalAttempt++
			if totalAttempt > 2 {
				// return nil, errSniffingTimeout
				return false
			}

			cReader.Cache(payload)
			if !payload.IsEmpty() {
				_, err := tls.SniffTLS(payload.Bytes())
				if err != common.ErrNoClue {
					// return result, err
					return true
				}
			}
			if payload.IsFull() {
				// return nil, errUnknownContent
				return false
			}
		}
	}
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

type wrappedConn struct {
	reader          buf.Reader
	remainderToRead []byte
	writer          buf.Writer
	conn            internet.Connection
}

func (c *wrappedConn) Read(b []byte) (n int, err error) {
	if len(c.remainderToRead) > 0 {
		size := copy(b, c.remainderToRead)
		c.remainderToRead = c.remainderToRead[size:]
		return size, nil
	}

	buf, err := c.reader.ReadMultiBuffer()
	if err != nil {
		return 0, err
	}
	bufLen := int(buf.Len())
	if bufLen > len(b) {
		c.remainderToRead = make([]byte, bufLen)
		buf.Copy(c.remainderToRead)
		size := copy(b, c.remainderToRead)
		c.remainderToRead = c.remainderToRead[size:]
		newError("Read: len(b): ", len(b), " hex: ", hex.EncodeToString(b)).WriteToLog()
		return size, nil
	} else {
		buf.Copy(b)
		newError("Read: len(b): ", len(b), " hex: ", hex.EncodeToString(b)).WriteToLog()
		return bufLen, nil
	}
}

func (c *wrappedConn) Write(b []byte) (n int, err error) {
	payload := buf.FromBytes(b)
	defer payload.Release()
	newError("Write: len(b): ", len(b), " hex: ", hex.EncodeToString(b)).WriteToLog()
	err = c.writer.WriteMultiBuffer([]*buf.Buffer{payload})
	return len(b), err
}

func (c *wrappedConn) Close() error {
	return c.conn.Close()
}

func (c *wrappedConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *wrappedConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *wrappedConn) SetDeadline(t time.Time) error {
	newError("SetDeadline").WriteToLog()
	return nil
}

func (c *wrappedConn) SetReadDeadline(t time.Time) error {
	newError("SetReadDeadline").WriteToLog()
	return nil

}

func (c *wrappedConn) SetWriteDeadline(t time.Time) error {
	newError("SetWriteDeadline").WriteToLog()
	return nil
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

type wrappedTLSConn struct {
	connInterceptor *ConnInterceptor
	conn            *gotls.Conn
}

func (c *wrappedTLSConn) Read(b []byte) (n int, err error) {
	dumper.queuePacket(&Packet{
		conn:    c.connInterceptor,
		time:    time.Now(),
		payload: b,
		upload:  true,
		raw:     false,
	})
	return c.conn.Read(b)
}

func (c *wrappedTLSConn) Write(b []byte) (n int, err error) {
	dumper.queuePacket(&Packet{
		conn:    c.connInterceptor,
		time:    time.Now(),
		payload: b,
		upload:  false,
		raw:     false,
	})
	return c.conn.Write(b)
}

func (c *wrappedTLSConn) Close() error {
	return c.conn.Close()
}

func (c *wrappedTLSConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *wrappedTLSConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *wrappedTLSConn) SetDeadline(t time.Time) error {
	newError("SetDeadline").WriteToLog()
	return nil
}

func (c *wrappedTLSConn) SetReadDeadline(t time.Time) error {
	newError("SetReadDeadline").WriteToLog()
	return nil

}

func (c *wrappedTLSConn) SetWriteDeadline(t time.Time) error {
	newError("SetWriteDeadline").WriteToLog()
	return nil
}
