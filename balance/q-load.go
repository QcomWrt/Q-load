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

type Backend struct {
	Addr  string
	alive atomic.Bool
}

type LoadBalancer struct {
	backends []*Backend
	rrCount  atomic.Uint64

	mu      sync.Mutex
	clients map[net.Conn]struct{}
}

func Start(lport string, tunnels []string) {
	if err := StartContext(context.Background(), lport, tunnels); err != nil {
		log.Printf("[Q-LOAD] stopped: %v", err)
	}
}

// StartContext menjalankan Q-load sampai context dibatalkan
// atau terjadi kesalahan pada listener.
func StartContext(ctx context.Context, lport string, tunnels []string) error {
	if ctx == nil {
		return errors.New("context tidak boleh nil")
	}
	if lport == "" || len(tunnels) == 0 {
		return errors.New("lport atau tunnels kosong")
	}

	lb := &LoadBalancer{
		clients: make(map[net.Conn]struct{}),
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

	log.Printf("[Q-LOAD] Listening on %s with %d backends",
		listenAddr, len(lb.backends))

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
// Daftar backend berasal dari supervisor Q-SSH.
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

	target, err := socks5Handshake(client)
	if err != nil {
		return
	}

	if ctx.Err() != nil {
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

func socks5Handshake(conn net.Conn) (string, error) {
	buf := make([]byte, 262)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", err
	}
	if buf[0] != 0x05 {
		return "", errors.New("invalid SOCKS version")
	}

	nMethods := int(buf[1])
	if nMethods == 0 {
		return "", errors.New("no SOCKS authentication methods")
	}

	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return "", err
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
		return "", errors.New("no supported SOCKS authentication method")
	}

	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", err
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		return "", errors.New("only SOCKS CONNECT is supported")
	}

	var host string

	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return "", err
		}
		host = net.IP(buf[:4]).String()

	case 0x03:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", err
		}

		n := int(buf[0])
		if n == 0 {
			return "", errors.New("empty domain")
		}

		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			return "", err
		}
		host = string(buf[:n])

	case 0x04:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return "", err
		}
		host = net.IP(buf[:16]).String()

	default:
		return "", errors.New("unsupported SOCKS address type")
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", err
	}

	port := binary.BigEndian.Uint16(buf[:2])
	if port == 0 {
		return "", errors.New("invalid destination port")
	}

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
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
