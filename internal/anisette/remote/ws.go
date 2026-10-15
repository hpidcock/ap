package remote

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hpidcock/ap/internal/httpx"
)

// A minimal RFC 6455 client: the provisioning session exchanges a handful of small JSON
// text frames, which does not justify a dependency. Fragmented messages, ping/pong and
// close are handled; extensions and subprotocols are not requested.

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// ErrClosed is returned once the peer has sent a close frame.
var ErrClosed = errors.New("websocket closed by peer")

type wsConn struct {
	conn net.Conn
	r    *bufio.Reader
}

// dialWS opens a websocket to rawURL (ws:// or wss://). timeout bounds the dial, the
// handshake and every subsequent read and write.
func dialWS(rawURL string, timeout time.Duration) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	host, port := u.Hostname(), u.Port()
	d := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	switch u.Scheme {
	case "wss":
		if port == "" {
			port = "443"
		}
		conn, err = tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, port), &tls.Config{
			RootCAs: httpx.RootPool(), MinVersion: tls.VersionTLS12, ServerName: host,
			InsecureSkipVerify: httpx.Insecure(), //nolint:gosec // opt-in debugging aid
		})
	case "ws":
		if port == "" {
			port = "80"
		}
		conn, err = d.Dial("tcp", net.JoinHostPort(host, port))
	default:
		return nil, fmt.Errorf("websocket: unsupported scheme %q", u.Scheme)
	}
	if err != nil {
		return nil, fmt.Errorf("websocket: connect %s: %w", u.Host, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	key := base64.StdEncoding.EncodeToString(nonce[:])
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: ap\r\n\r\n", path, u.Host, key)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("websocket: handshake: %w", err)
	}
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, &http.Request{Method: http.MethodGet})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("websocket: handshake: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		conn.Close()
		return nil, fmt.Errorf("websocket: server answered HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), acceptKey(key); got != want {
		conn.Close()
		return nil, fmt.Errorf("websocket: bad Sec-WebSocket-Accept")
	}
	return &wsConn{conn: conn, r: r}, nil
}

func acceptKey(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}

// writeFrame sends one masked frame (clients must mask).
func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	var hdr []byte
	hdr = append(hdr, 0x80|opcode)
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n < 1<<16:
		hdr = append(hdr, 0x80|126)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n))
	default:
		hdr = append(hdr, 0x80|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	hdr = append(hdr, mask[:]...)
	masked := make([]byte, n)
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	_, err := c.conn.Write(append(hdr, masked...))
	return err
}

// readFrame reads one frame, unmasking it if the peer masked it.
func (c *wsConn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(c.r, h[:]); err != nil {
		return false, 0, nil, err
	}
	fin, opcode = h[0]&0x80 != 0, h[0]&0x0f
	masked := h[1]&0x80 != 0
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.r, ext[:]); err != nil {
			return false, 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.r, ext[:]); err != nil {
			return false, 0, nil, err
		}
		n = binary.BigEndian.Uint64(ext[:])
	}
	if n > 1<<20 {
		return false, 0, nil, fmt.Errorf("websocket: frame of %d bytes is too large", n)
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(c.r, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(c.r, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, opcode, payload, nil
}

// ReadText returns the next complete text message, answering pings on the way.
func (c *wsConn) ReadText() (string, error) {
	var msg []byte
	for {
		fin, op, payload, err := c.readFrame()
		if err != nil {
			return "", fmt.Errorf("websocket: read: %w", err)
		}
		switch op {
		case opClose:
			reason := ""
			if len(payload) >= 2 {
				reason = fmt.Sprintf(" (code %d %s)", binary.BigEndian.Uint16(payload), strings.TrimSpace(string(payload[2:])))
			}
			_ = c.writeFrame(opClose, payload)
			return "", fmt.Errorf("%w%s", ErrClosed, reason)
		case opPing:
			if err := c.writeFrame(opPong, payload); err != nil {
				return "", err
			}
		case opPong:
		case opText, opBinary, opContinuation:
			msg = append(msg, payload...)
			if fin {
				return string(msg), nil
			}
		default:
			return "", fmt.Errorf("websocket: unexpected opcode %#x", op)
		}
	}
}

// WriteText sends one text message.
func (c *wsConn) WriteText(s string) error {
	if err := c.writeFrame(opText, []byte(s)); err != nil {
		return fmt.Errorf("websocket: write: %w", err)
	}
	return nil
}

// Close sends a normal-closure frame and closes the connection.
func (c *wsConn) Close() error {
	_ = c.writeFrame(opClose, []byte{0x03, 0xe8})
	return c.conn.Close()
}
