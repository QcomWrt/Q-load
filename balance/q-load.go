// Package balance berisi Q-load: load balancer SOCKS5 lokal yang
// meneruskan koneksi ke backend SOCKS5 (worker Q-SSH atau Clash).
//
// Paket ini hanya memakai standar library Go, sehingga bisa dibangun
// untuk Linux, Windows, Android, dan OpenWrt tanpa kode khusus platform.
package balance

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// maxDNSInFlight membatasi jumlah query DNS yang diproses bersamaan.
// Paket di atas batas ini dibuang agar memori dan worker SSH tidak jebol.
const maxDNSInFlight = 32

// Options mengatur perilaku Q-load. Nilai nol berarti perilaku lama
// (tanpa dukungan UDP), sehingga pemanggil lama tidak terpengaruh.
type Options struct {
	// UDPDNS mengaktifkan UDP ASSOCIATE untuk query DNS (port 53),
	// yang diteruskan lewat DNS over TCP ke backend.
	UDPDNS bool
}

type Backend struct {
	Addr  string
	alive atomic.Bool
}

type LoadBalancer struct {
	backends []*Backend
	rrCount  atomic.Uint64
	udpDNS   bool
	dnsSem   chan struct{}

	mu      sync.Mutex
	clients map[net.Conn]struct{}
}

// Start menjalankan Q-load tanpa dukungan UDP (perilaku lama).
func Start(lport string, tunnels []string) {
	if err := StartContext(context.Background(), lport, tunnels); err != nil {
		log.Printf("[Q-LOAD] stopped: %v", err)
	}
}

// StartContext menjalankan Q-load tanpa dukungan UDP sampai context
// dibatalkan atau terjadi kesalahan pada listener.
func StartContext(ctx context.Context, lport string, tunnels []string) error {
	return StartContextWithOptions(ctx, lport, tunnels, Options{})
}

// StartContextWithOptions menjalankan Q-load dengan opsi tertentu.
func StartContextWithOptions(
	ctx context.Context,
	lport string,
	tunnels []string,
	opts Options,
) error {
	if ctx == nil {
		return errors.New("context tidak boleh nil")
	}
	if lport == "" || len(tunnels) == 0 {
		return errors.New("lport atau tunnels kosong")
	}

	lb := &LoadBalancer{
		clients: make(map[net.Conn]struct{}),
		udpDNS:  opts.UDPDNS,
		dnsSem:  make(chan struct{}, maxDNSInFlight),
	}

	for _, addr := range tunnels {
		if addr == "" {
			return errors.New("alamat backend kosong")
		}

		backend := &Backend{Addr: addr}
		backend.alive.Store(true)
		lb.backends = append(lb.backends, backend)
	}

	listenAddr := net.JoinHostPort("127.0.0.1", lport)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}

	log.Printf("[Q-LOAD] Listening on %s with %d backends (udp-dns=%t)",
		listenAddr, len(lb.backends), lb.udpDNS)

	var wg sync.WaitGroup

	// Membatalkan context akan menutup listener dan semua
	// koneksi klien supaya Accept/handler tidak tertahan.
	stopClose := context.AfterFunc(ctx, func() {
		_ = ln.Close()
		lb.closeClients()
	})
	defer stopClose()

	for {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				break
			}

			_ = ln.Close()
			lb.closeClients()
			wg.Wait()

			return fmt.Errorf("accept: %w", acceptErr)
		}

		if ctx.Err() != nil {
			_ = conn.Close()
			break
		}

		lb.mu.Lock()

		// Jangan menerima koneksi baru setelah shutdown dimulai.
		if ctx.Err() != nil {
			lb.mu.Unlock()
			_ = conn.Close()
			break
		}

		lb.clients[conn] = struct{}{}
		lb.mu.Unlock()

		wg.Add(1)

		go func(c net.Conn) {
			defer wg.Done()
			defer func() {
				lb.mu.Lock()
				delete(lb.clients, c)
				lb.mu.Unlock()

				_ = c.Close()
			}()

			lb.handleClient(ctx, c)
		}(conn)
	}

	_ = ln.Close()
	lb.closeClients()
	wg.Wait()

	log.Printf("[Q-LOAD] stopped")
	return nil
}

// closeClients menutup semua koneksi klien yang masih tercatat.
func (lb *LoadBalancer) closeClients() {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for conn := range lb.clients {
		_ = conn.Close()
	}
}

// selectBackend memilih backend secara round-robin.
// Daftar backend berasal dari supervisor Q-SSH atau konfigurasi Clash.
func (lb *LoadBalancer) selectBackend() *Backend {
	alive := make([]*Backend, 0, len(lb.backends))

	for _, backend := range lb.backends {
		if backend.alive.Load() {
			alive = append(alive, backend)
		}
	}

	if len(alive) == 0 {
		return nil
	}

	idx := lb.rrCount.Add(1) - 1
	return alive[idx%uint64(len(alive))]
}

func (lb *LoadBalancer) handleClient(ctx context.Context, client net.Conn) {
	stopClose := context.AfterFunc(ctx, func() {
		_ = client.Close()
	})
	defer stopClose()

	cmd, target, err := socks5Handshake(client)
	if err != nil {
		return
	}

	if ctx.Err() != nil {
		return
	}

	// UDP ASSOCIATE: hanya aktif jika opsi UDPDNS diaktifkan.
	// Jika tidak, klien menerima "command not supported" (0x07).
	if cmd == 0x03 {
		if !lb.udpDNS {
			_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}

		lb.handleUDPAssociate(ctx, client)
		return
	}

	backend := lb.selectBackend()
	if backend == nil {
		_, _ = client.Write([]byte{
			0x05, 0x04, 0x00, 0x01,
			0, 0, 0, 0, 0, 0,
		})
		log.Printf("[Q-LOAD] no backend available")
		return
	}

	remote, err := socks5Dial(backend.Addr, target)
	if err != nil {
		_, _ = client.Write([]byte{
			0x05, 0x01, 0x00, 0x01,
			0, 0, 0, 0, 0, 0,
		})

		log.Printf("[Q-LOAD] backend connection failed %s: %v",
			backend.Addr, err)
		return
	}
	defer remote.Close()

	if ctx.Err() != nil {
		return
	}

	// Kirim balasan sukses hanya setelah backend terhubung.
	if _, err := client.Write([]byte{
		0x05, 0x00, 0x00, 0x01,
		0, 0, 0, 0, 0, 0,
	}); err != nil {
		return
	}

	log.Printf("[CONNECT] %s via %s", target, backend.Addr)

	errCh := make(chan struct{}, 2)

	go func() {
		_, _ = io.Copy(remote, client)
		errCh <- struct{}{}
	}()

	go func() {
		_, _ = io.Copy(client, remote)
		errCh <- struct{}{}
	}()

	select {
	case <-ctx.Done():
	case <-errCh:
	}

	// Mengakhiri kedua arah relay.
	_ = client.Close()
	_ = remote.Close()
}

// handleUDPAssociate membuka socket UDP lokal untuk klien.
// Relay berhenti saat koneksi kontrol TCP ditutup.
func (lb *LoadBalancer) handleUDPAssociate(ctx context.Context, client net.Conn) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		log.Printf("[UDP] listen failed: %v", err)
		return
	}
	defer relay.Close()

	port := relay.LocalAddr().(*net.UDPAddr).Port

	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(reply[8:], uint16(port))
	if _, err := client.Write(reply); err != nil {
		return
	}

	// Ketika klien menutup kontrol TCP, relay UDP ikut berhenti.
	go func() {
		_, _ = io.Copy(io.Discard, client)
		_ = relay.Close()
	}()

	log.Printf("[UDP] associate on 127.0.0.1:%d", port)

	buf := make([]byte, 65535)
	for {
		n, src, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		// Batasi konkurensi. Jika penuh, paket dibuang (DNS akan retry).
		select {
		case lb.dnsSem <- struct{}{}:
			go func() {
				defer func() { <-lb.dnsSem }()
				lb.relayDNS(relay, src, pkt)
			}()
		default:
			log.Printf("[UDP] DNS queue full, dropping packet")
		}
	}
}

// relayDNS meneruskan satu paket UDP SOCKS5 berisi query DNS (port 53).
// Paket dengan tujuan lain dibuang.
func (lb *LoadBalancer) relayDNS(relay *net.UDPConn, src *net.UDPAddr, pkt []byte) {
	target, headerLen, err := parseSocksUDP(pkt)
	if err != nil {
		return
	}

	_, portStr, err := net.SplitHostPort(target)
	if err != nil || portStr != "53" {
		return
	}

	backend := lb.selectBackend()
	if backend == nil {
		return
	}

	answer, err := dnsOverTCP(backend.Addr, target, pkt[headerLen:])
	if err != nil {
		log.Printf("[UDP] DNS %s via %s failed: %v", target, backend.Addr, err)
		return
	}

	out := make([]byte, 0, headerLen+len(answer))
	out = append(out, pkt[:headerLen]...)
	out = append(out, answer...)

	_, _ = relay.WriteToUDP(out, src)
}

// parseSocksUDP membaca header UDP SOCKS5 (RFC 1928).
// Mengembalikan alamat tujuan dan panjang header.
func parseSocksUDP(pkt []byte) (string, int, error) {
	// RSV(2) FRAG(1) ATYP(1)
	if len(pkt) < 4 {
		return "", 0, errors.New("UDP packet too short")
	}
	if pkt[2] != 0x00 {
		return "", 0, errors.New("fragmented UDP packet not supported")
	}

	off := 4
	var host string

	switch pkt[3] {
	case 0x01:
		if len(pkt) < off+4 {
			return "", 0, errors.New("truncated IPv4 address")
		}
		host = net.IP(pkt[off : off+4]).String()
		off += 4

	case 0x03:
		if len(pkt) < off+1 {
			return "", 0, errors.New("truncated domain length")
		}
		n := int(pkt[off])
		off++
		if n == 0 || len(pkt) < off+n {
			return "", 0, errors.New("truncated domain")
		}
		host = string(pkt[off : off+n])
		off += n

	case 0x04:
		if len(pkt) < off+16 {
			return "", 0, errors.New("truncated IPv6 address")
		}
		host = net.IP(pkt[off : off+16]).String()
		off += 16

	default:
		return "", 0, errors.New("unsupported UDP address type")
	}

	if len(pkt) < off+2 {
		return "", 0, errors.New("truncated UDP port")
	}
	port := binary.BigEndian.Uint16(pkt[off : off+2])
	off += 2

	if port == 0 {
		return "", 0, errors.New("invalid UDP destination port")
	}

	return net.JoinHostPort(host, strconv.Itoa(int(port))), off, nil
}

// dnsOverTCP mengirim query DNS ke target melalui backend SOCKS5
// dengan framing TCP (prefix panjang 2 byte).
func dnsOverTCP(backendAddr, target string, query []byte) ([]byte, error) {
	if len(query) == 0 || len(query) > 65535 {
		return nil, errors.New("invalid DNS query size")
	}

	conn, err := socks5Dial(backendAddr, target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	msg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(msg, uint16(len(query)))
	copy(msg[2:], query)

	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}

	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 {
		return nil, errors.New("empty DNS response")
	}

	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// socks5Handshake membaca handshake dan request SOCKS5 dari klien.
// Mengembalikan command (0x01 CONNECT atau 0x03 UDP ASSOCIATE) dan alamat tujuan.
func socks5Handshake(conn net.Conn) (byte, string, error) {
	buf := make([]byte, 262)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return 0, "", err
	}
	if buf[0] != 0x05 {
		return 0, "", errors.New("invalid SOCKS version")
	}

	nMethods := int(buf[1])
	if nMethods == 0 {
		return 0, "", errors.New("no SOCKS authentication methods")
	}

	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return 0, "", err
	}

	hasNoAuth := false
	for _, method := range buf[:nMethods] {
		if method == 0x00 {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		_, _ = conn.Write([]byte{0x05, 0xFF})
		return 0, "", errors.New("no supported SOCKS authentication method")
	}

	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return 0, "", err
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return 0, "", err
	}
	if buf[0] != 0x05 {
		return 0, "", errors.New("invalid SOCKS request version")
	}

	cmd := buf[1]
	if cmd != 0x01 && cmd != 0x03 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return 0, "", errors.New("unsupported SOCKS command")
	}

	var host string

	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return 0, "", err
		}
		host = net.IP(buf[:4]).String()

	case 0x03:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return 0, "", err
		}

		n := int(buf[0])
		if n == 0 {
			return 0, "", errors.New("empty domain")
		}

		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			return 0, "", err
		}
		host = string(buf[:n])

	case 0x04:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return 0, "", err
		}
		host = net.IP(buf[:16]).String()

	default:
		return 0, "", errors.New("unsupported SOCKS address type")
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return 0, "", err
	}

	port := binary.BigEndian.Uint16(buf[:2])

	// UDP ASSOCIATE sering memakai 0.0.0.0:0 sebagai tujuan awal,
	// sehingga port 0 hanya ditolak untuk CONNECT.
	if port == 0 && cmd == 0x01 {
		return 0, "", errors.New("invalid destination port")
	}

	return cmd, net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// socks5Dial membuka koneksi ke backend SOCKS5 dan meminta koneksi
// menuju target. Deadline membatasi waktu handshake yang macet.
func socks5Dial(proxyAddr, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	fail := func(err error) (net.Conn, error) {
		_ = conn.Close()
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fail(err)
	}

	buf := make([]byte, 2)
	if _, err = io.ReadFull(conn, buf); err != nil {
		return fail(err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		return fail(errors.New("backend SOCKS authentication failed"))
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fail(err)
	}

	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fail(errors.New("invalid destination port"))
	}

	req := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(host)

	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		req = append(req, 0x04)
		req = append(req, ip6...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fail(errors.New("invalid domain length"))
		}

		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(portNum))
	req = append(req, pb...)

	if _, err = conn.Write(req); err != nil {
		return fail(err)
	}

	header := make([]byte, 4)
	if _, err = io.ReadFull(conn, header); err != nil {
		return fail(err)
	}
	if header[0] != 0x05 || header[1] != 0x00 {
		return fail(fmt.Errorf("backend SOCKS CONNECT failed: reply=%d", header[1]))
	}

	switch header[3] {
	case 0x01:
		_, err = io.CopyN(io.Discard, conn, 4+2)

	case 0x03:
		var n [1]byte
		if _, err = io.ReadFull(conn, n[:]); err == nil {
			_, err = io.CopyN(io.Discard, conn, int64(n[0])+2)
		}

	case 0x04:
		_, err = io.CopyN(io.Discard, conn, 16+2)

	default:
		err = errors.New("invalid backend SOCKS reply address type")
	}

	if err != nil {
		return fail(err)
	}

	// Handshake selesai; hapus deadline agar koneksi bisa terus digunakan.
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return fail(err)
	}

	return conn, nil
}