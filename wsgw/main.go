// wsgw: WebSocket -> UDP gateway for the PCA Phobos "Keenetic cloud" transport.
// Keenetic `ip http proxy` (KeenDNS cloud, TLS on the router) forwards wss://<sub>/ here as plain ws.
// One binary WS message = one obfuscated UDP packet; each WS connection gets its own UDP socket to -t.
package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func main() {
	listen := flag.String("l", "0.0.0.0:18090", "listen addr (http)")
	target := flag.String("t", "", "UDP target host:port (server obfuscator)")
	flag.Parse()
	if *target == "" {
		log.Fatal("-t host:port required")
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "ok", http.StatusUpgradeRequired)
			return
		}
		h, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, rw, err := h.Hijack()
		if err != nil {
			return
		}
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + wsGUID))
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
			base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
		rw.Flush()
		go serve(conn, rw.Reader, *target)
	})
	log.Printf("wsgw %s -> udp %s", *listen, *target)
	log.Fatal(http.ListenAndServe(*listen, nil))
}

func serve(c net.Conn, br *bufio.Reader, target string) {
	defer c.Close()
	u, err := net.Dial("udp", target)
	if err != nil {
		log.Printf("udp %s: %v", target, err)
		return
	}
	defer u.Close()
	go func() { // udp -> ws
		buf := make([]byte, 65535)
		for {
			u.SetReadDeadline(time.Now().Add(5 * time.Minute))
			n, err := u.Read(buf)
			if err != nil {
				c.Close()
				return
			}
			if writeFrame(c, 2, buf[:n]) != nil {
				return
			}
		}
	}()
	for { // ws -> udp
		op, p, err := readFrame(br)
		if err != nil {
			return
		}
		switch op {
		case 2, 0:
			u.Write(p)
		case 8:
			return
		case 9:
			writeFrame(c, 10, p)
		}
	}
}

// readFrame reads one client frame (masked). Fragmented messages are not used by our clients.
func readFrame(r *bufio.Reader) (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var e [2]byte
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(e[:]))
	case 127:
		var e [8]byte
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return 0, nil, err
		}
		n = binary.BigEndian.Uint64(e[:])
	}
	if n > 65535 {
		return 0, nil, io.ErrUnexpectedEOF
	}
	var mask [4]byte
	masked := h[1]&0x80 != 0
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range p {
			p[i] ^= mask[i&3]
		}
	}
	return h[0] & 0x0f, p, nil
}

func writeFrame(w io.Writer, op byte, p []byte) error {
	hdr := []byte{0x80 | op, 0}
	switch n := len(p); {
	case n < 126:
		hdr[1] = byte(n)
	case n < 65536:
		hdr[1] = 126
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n))
	default:
		hdr[1] = 127
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	_, err := w.Write(append(hdr, p...))
	return err
}
