package masque

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	uriTemplateTargetHost = "target_host"
	uriTemplateTargetPort = "target_port"
)

const datagramCapsuleType = 0x00

const maxUDPPayloadSize = 1500

var contextIDZero = quicvarint.Append([]byte{}, 0)

type proxyEntry struct {
	str  *http3.Stream
	conn ProxyConn
}

// ProxyConn is a connection used to communicate with endpoints we're proxying to
// It primarily has PacketConn semantics, since we intend on sending and receiving
// datagrams, but it needs to provide net.Conn functionality for convenience. This will
// typically be a *net.UDPConn, but you may use another concrete implementation wrapping
// one to add semantics (e.g. stats).
type ProxyConn interface {
	net.PacketConn
	net.Conn
}

func (e proxyEntry) Close() error {
	e.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
	return errors.Join(e.str.Close(), e.conn.Close())
}

func isCleanShutdownError(err error) bool {
	// These errors are expected when the proxy is shutting down.
	var qErr *quic.StreamError
	if errors.As(err, &qErr) && qErr.ErrorCode == quic.StreamErrorCode(http3.ErrCodeConnectError) && !qErr.Remote {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err.Error() == "use of closed network connection" {
		return true
	}
	if errors.Is(err, io.ErrClosedPipe) {
		return true
	}

	// These errors are expected when the connection is closed.
	var h3Err *http3.Error
	if errors.As(err, &h3Err) && h3Err.ErrorCode == 0x0 && !h3Err.Remote {
		return true
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) && appErr.ErrorCode == 0x0 {
		return true
	}

	return false
}

// A Proxy is an RFC 9298 CONNECT-UDP proxy.
type Proxy struct {
	// EnableDatagrams must match QUICConfig.EnableDatagrams,
	// Transport.EnableDatagrams, and Settings.EnableDatagrams.
	// It is required here because there is no way to recover the QUICConfig,
	// Transport, or local Settings from the request or response.
	EnableDatagrams bool

	mx       sync.Mutex
	closed   bool
	refCount sync.WaitGroup // counter for the Go routines spawned in Upgrade
	closers  map[io.Closer]struct{}
}

func errToStatus(err error) int {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// Consistent with RFC 9209 Section 2.3.1.
		return http.StatusGatewayTimeout
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		// Recommended by RFC 9209 Section 2.3.2.
		return http.StatusBadGateway
	}
	var addrErr *net.AddrError
	var parseError *net.ParseError
	if errors.As(err, &addrErr) || errors.As(err, &parseError) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func dnsErrorToProxyStatus(proxyStatus *httpsfv.Item, dnsError *net.DNSError) {
	if dnsError.Timeout() {
		proxyStatus.Params.Add("error", "dns_timeout")
	} else {
		proxyStatus.Params.Add("error", "dns_error")
		if dnsError.IsNotFound {
			// "Negative response" isn't a real RCODE, but it is included
			// in RFC 8499 Section 3 as a sort of meta/pseudo-RCODE like NODATA,
			// and this section is referenced by the definition of the "rcode"
			// parameter.
			proxyStatus.Params.Add("rcode", "Negative response")
		} else {
			// DNS intermediaries normally convert miscellaneous errors to SERVFAIL.
			proxyStatus.Params.Add("rcode", "SERVFAIL")
		}
	}
}

// Proxy proxies a request on a newly created connected UDP socket.
// For more control over the UDP socket, use ProxyConnectedSocket.
// Applications may add custom header fields to the response header,
// but MUST NOT call WriteHeader on the http.ResponseWriter.
func (s *Proxy) Proxy(w http.ResponseWriter, r *Request) error {
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}
	s.mx.Unlock()

	proxyStatus := httpsfv.NewItem(r.Host)
	// Adds the proxy status to the header.  Returns
	// the input error, or a new one if serialization fails.
	writeProxyStatus := func(err error) error {
		if err != nil {
			proxyStatus.Params.Add("details", err.Error())
		}
		proxyStatusVal, marshalErr := httpsfv.Marshal(proxyStatus)
		if marshalErr != nil {
			return marshalErr
		}
		w.Header().Add("Proxy-Status", proxyStatusVal)
		return err
	}

	addr, err := net.ResolveUDPAddr("udp", r.Target)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
			dnsErrorToProxyStatus(&proxyStatus, dnsError)
		}
		err = writeProxyStatus(err)
		w.WriteHeader(errToStatus(err))
		return err
	}
	proxyStatus.Params.Add("next-hop", addr.String())

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		proxyStatus.Params.Add("error", "destination_ip_unroutable")
		err = writeProxyStatus(err)
		w.WriteHeader(errToStatus(err))
		return err
	}
	defer conn.Close()

	if err = writeProxyStatus(nil); err != nil {
		w.WriteHeader(errToStatus(err))
		return err
	}
	return s.ProxyConnectedSocket(w, r, conn)
}

func hijackIfH1(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, error) {
	hijacker, isH1 := w.(http.Hijacker)
	if !isH1 {
		return nil, nil, nil
	}
	return hijacker.Hijack()
}

func writeResponseWithHijacker(headers http.Header, httpConn net.Conn, buf *bufio.ReadWriter, protocol string) error {
	statusCode := http.StatusSwitchingProtocols
	if buf.Reader.Buffered() > 0 {
		statusCode = http.StatusBadRequest
		if proxyStatusVals := headers.Values("Proxy-Status"); len(proxyStatusVals) > 0 {
			proxyStatus, err := httpsfv.UnmarshalItem(proxyStatusVals)
			if err != nil {
				return fmt.Errorf("encountered invalid Proxy-Status: %w", err)
			}
			proxyStatus.Params.Add("error", "proxy_internal_response")
			proxyStatus.Params.Add("detail",
				fmt.Sprintf("client sent %d bytes of optimistic data, not allowed in HTTP/1.1", buf.Available()))
			newProxyStatusVal, err := httpsfv.Marshal(proxyStatus)
			if err != nil {
				return fmt.Errorf("Couldn't serialize Proxy-Status: %w", err)
			}
			headers.Set("Proxy-Status", newProxyStatusVal)
		}
	}

	rsp := http.Response{
		StatusCode:    statusCode,
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: -1,
		Header:        headers,
	}
	if statusCode == http.StatusSwitchingProtocols {
		rsp.Header.Set("Connection", "Upgrade")
		rsp.Header.Set("Upgrade", protocol)
	}
	rspBytes, err := httputil.DumpResponse(&rsp, false)
	if err != nil {
		return err
	}
	if _, err := httpConn.Write(rspBytes); err != nil {
		return err
	}
	return nil
}

// ProxyConnectedSocket proxies a request on a connected UDP socket.
// Applications may add custom header fields such as Proxy-Status
// to the response header, but MUST NOT call WriteHeader on the
// http.ResponseWriter. It closes the connection before returning.
func (s *Proxy) ProxyConnectedSocket(w http.ResponseWriter, r *Request, conn ProxyConn) error {
	s.mx.Lock()
	if s.closed {
		s.mx.Unlock()
		conn.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return net.ErrClosed
	}

	var closer io.Closer
	if s.closers == nil {
		s.closers = make(map[io.Closer]struct{})
	}

	s.refCount.Add(1)
	defer s.refCount.Done()

	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	h1Conn, buf, err := hijackIfH1(w)
	if err != nil {
		return err
	}
	if h1Conn != nil {
		defer h1Conn.Close()

		// The request body is no longer relevant due to hijack.  Use the
		// hijacked connection instead.
		closer = h1Conn
		s.closers[closer] = struct{}{}
		s.mx.Unlock()

		if err := writeResponseWithHijacker(w.Header(), h1Conn, buf, requestProtocol); err != nil {
			return err
		}

		forwardUDP(nil, h1Conn, h1Conn, conn)
	} else {
		w.WriteHeader(http.StatusOK)

		str := w.(http3.HTTPStreamer).HTTPStream()

		closer = proxyEntry{str: str, conn: conn}
		s.closers[closer] = struct{}{}
		s.mx.Unlock()

		var dgs DatagramSendReceiver
		if s.EnableDatagrams && clientAcceptsDatagrams(w) {
			dgs = str
		}
		forwardUDP(dgs, w, str, conn)
		str.Close()
	}

	s.mx.Lock()
	delete(s.closers, closer)
	s.mx.Unlock()
	return nil
}

type DatagramSender interface {
	SendDatagram(b []byte) error
	io.Closer
}

type DatagramReceiver interface {
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	CancelRead(quic.StreamErrorCode)
}

// DatagramSendReceiver is the common datagram interface of
// [http3.Stream] and [http3.RequestStream].
type DatagramSendReceiver interface {
	DatagramSender
	DatagramReceiver
}

var _ DatagramSendReceiver = &http3.Stream{}
var _ DatagramSendReceiver = &http3.RequestStream{}

// Returns true if the client has offered to receive datagrams.
func clientAcceptsDatagrams(w http.ResponseWriter) bool {
	hijacker, ok := w.(http3.Hijacker)
	if !ok {
		return false
	}

	h3Connection := hijacker.Connection()
	<-h3Connection.ReceivedSettings()
	remoteSettings := h3Connection.Settings()
	return remoteSettings.EnableDatagrams
}

/*
 * Forwarding function conventions:
 * `*To*` functions block until that direction of forwarding is complete.
 * They return `nil` (not EOF) on clean shutdown.
 * `str`, `w`, and `r` represent the HTTP side.
 * `conn` represents the raw UDP or TCP side.
 */

// `r`, `w`, and `conn` are required.
// `str` indicates Datagram support if non-nil.
func forwardUDP(str DatagramSendReceiver, w io.Writer, r io.ReadCloser, conn net.Conn) {
	var wg sync.WaitGroup
	if str != nil {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := udpToDatagrams(str, conn); err != nil && !isCleanShutdownError(err) {
				log.Printf("proxying %s to datagrams stopped: %v", conn.RemoteAddr(), err)
			}
			r.Close()
		}()
		go func() {
			defer wg.Done()
			if err := datagramsToUDP(conn, str); err != nil && !isCleanShutdownError(err) {
				log.Printf("proxying datagrams to %s failed: %v", conn.RemoteAddr(), err)
			}
		}()
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := udpToCapsules(w, conn); err != nil && !isCleanShutdownError(err) {
				log.Printf("writing to HTTP stream failed: %v", err)
			}
			r.Close()
		}()
	}

	// The remote peer can always choose to send capsules.
	if err := capsulesToUDP(conn, r); err != nil && !isCleanShutdownError(err) {
		log.Printf("reading from HTTP stream failed: %#v", err)
	}
	conn.Close()
	wg.Wait()
}

func datagramsToUDP(conn io.Writer, str DatagramReceiver) error {
	for {
		data, err := str.ReceiveDatagram(context.Background())
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		contextID, n, err := quicvarint.Parse(data)
		if err != nil {
			return err
		}
		if contextID != 0 {
			// Drop this datagram. We currently only support proxying of UDP payloads.
			continue
		}
		if len(data[n:]) > maxUDPPayloadSize {
			log.Printf("dropping datagram larger than MTU (%d > %d)", len(data[n:]), maxUDPPayloadSize)
			continue
		}
		if _, err := conn.Write(data[n:]); err != nil {
			return err
		}
	}
}

func udpToDatagrams(str DatagramSender, conn io.Reader) error {
	b := make([]byte, len(contextIDZero)+maxUDPPayloadSize+1)
	copy(b, contextIDZero)
	for {
		n, err := conn.Read(b[len(contextIDZero):])
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n > maxUDPPayloadSize {
			log.Printf("dropping UDP packet larger than MTU")
			continue
		}
		if err := str.SendDatagram(b[:len(contextIDZero)+n]); err != nil {
			return err
		}
	}
}

func capsulesToUDP(conn io.Writer, body io.Reader) error {
	qr := quicvarint.NewReader(body)
	b := make([]byte, maxUDPPayloadSize+1)
	for {
		capsuleType, content, err := http3.ParseCapsule(qr)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if capsuleType != datagramCapsuleType {
			log.Printf("skipping unknown capsule type %d", capsuleType)
			continue
		}
		n, err := readAll(content, b)
		if n > maxUDPPayloadSize {
			// Drain remainder of oversize capsule
			remainder, err := io.Copy(io.Discard, content)
			if err != nil {
				return err
			}
			log.Printf("skipped datagram capsule larger than MTU (%d > %d)", int64(n)+remainder, maxUDPPayloadSize)
			continue
		}
		if err != nil {
			return err
		}
		if _, err := conn.Write(b[:n]); err != nil {
			return err
		}
	}
}

// Read all the data from r until EOF.  If this doesn't fit in b,
// ErrShortBuffer is returned.
func readAll(r io.Reader, b []byte) (int, error) {
	blen := 0
	for blen < len(b) {
		n, err := r.Read(b[blen:])
		blen += n
		if err != nil {
			if errors.Is(err, io.EOF) {
				return blen, nil
			}
			return blen, err
		}
	}
	return blen, io.ErrShortBuffer
}

func udpToCapsules(w io.Writer, conn io.Reader) error {
	qw := quicvarint.NewWriter(w)
	b := make([]byte, maxUDPPayloadSize+1)
	for {
		n, err := conn.Read(b)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n > maxUDPPayloadSize {
			log.Printf("dropping UDP packet larger than MTU")
			continue
		}
		if err := http3.WriteCapsule(qw, datagramCapsuleType, b[:n]); err != nil {
			return err
		}
	}
}

// Close closes the proxy, immediately terminating all proxied flows.
func (s *Proxy) Close() error {
	s.mx.Lock()
	s.closed = true
	var errs []error
	for closer := range s.closers {
		errs = append(errs, closer.Close())
	}
	s.mx.Unlock()

	s.refCount.Wait()
	s.closers = nil
	return errors.Join(errs...)
}
