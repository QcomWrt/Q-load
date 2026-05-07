// q-load.go
//
// Build:
//   go build -o q-load q-load.go
//
// Example:
//   ./q-load -lport 7777 -tunnel 127.0.0.1:1080 127.0.0.1:1081 127.0.0.1:1082
//
// Style:
//   Mirip syntax ZiVPN Android:
//   libload -lport 7777 -tunnel <backend1> <backend2> <backend3> ...
//
// Fungsi:
// - SOCKS5 inbound local di 127.0.0.1:<lport>
// - Merge banyak SOCKS5 backend
// - Round Robin default
// - Health check backend
// - Fail skip backend mati
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

type Backend struct {
	Addr  string
	Alive bool
}

var (
	backends []*Backend
	rrCount  uint64
)

func main() {
	lport, tunnels := parseArgs()

	if lport == "" || len(tunnels) == 0 {
		fmt.Println("Usage:")
		fmt.Println("  q-load -lport 7777 -tunnel 127.0.0.1:1080 127.0.0.1:1081")
		os.Exit(1)
	}

	for _, t := range tunnels {
		backends = append(backends, &Backend{
			Addr: t,
		})
	}

	go healthLoop()

	listenAddr := "127.0.0.1:" + lport
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}

	log.Printf("[Q-LOAD] Listening on %s with %d tunnels", listenAddr, len(backends))

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn)
	}
}

func parseArgs() (string, []string) {
	args := os.Args[1:]

	var lport string
	var tunnels []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-lport":
			if i+1 < len(args) {
				lport = args[i+1]
				i++
			}
		case "-tunnel":
			for j := i + 1; j < len(args); j++ {
				if len(args[j]) > 0 && args[j][0] == '-' {
					break
				}
				tunnels = append(tunnels, args[j])
				i = j
			}
		}
	}

	return lport, tunnels
}

func healthLoop() {
	for {
		for _, be := range backends {
			c, err := net.DialTimeout("tcp", be.Addr, 3*time.Second)
			if err != nil {
				be.Alive = false
				continue
			}
			be.Alive = true
			_ = c.Close()
		}

		alive := 0
		for _, be := range backends {
			if be.Alive {
				alive++
			}
		}

		log.Printf("[HEALTH] alive=%d/%d", alive, len(backends))
		time.Sleep(10 * time.Second)
	}
}

func selectBackend() *Backend {
	var alive []*Backend

	for _, be := range backends {
		if be.Alive {
			alive = append(alive, be)
		}
	}

	if len(alive) == 0 {
		return nil
	}

	idx := atomic.AddUint64(&rrCount, 1)
	return alive[int(idx)%len(alive)]
}

func handleClient(client net.Conn) {
	defer client.Close()

	target, err := socks5Handshake(client)
	if err != nil {
		return
	}

	backend := selectBackend()
	if backend == nil {
		log.Printf("[ERROR] no backend alive")
		return
	}

	remote, err := socks5Dial(backend.Addr, target)
	if err != nil {
		log.Printf("[ERROR] backend failed %s", backend.Addr)
		backend.Alive = false
		return
	}
	defer remote.Close()

	log.Printf("[CONNECT] %s via %s", target, backend.Addr)

	go io.Copy(remote, client)
	io.Copy(client, remote)
}

func socks5Handshake(conn net.Conn) (string, error) {
	buf := make([]byte, 262)

	_, err := io.ReadFull(conn, buf[:2])
	if err != nil {
		return "", err
	}

	nMethods := int(buf[1])
	_, err = io.ReadFull(conn, buf[:nMethods])
	if err != nil {
		return "", err
	}

	_, err = conn.Write([]byte{0x05, 0x00})
	if err != nil {
		return "", err
	}

	_, err = io.ReadFull(conn, buf[:4])
	if err != nil {
		return "", err
	}

	if buf[1] != 0x01 {
		return "", errors.New("only connect supported")
	}

	atyp := buf[3]
	var host string

	switch atyp {
	case 0x01:
		_, err = io.ReadFull(conn, buf[:4])
		if err != nil {
			return "", err
		}
		host = net.IP(buf[:4]).String()

	case 0x03:
		_, err = io.ReadFull(conn, buf[:1])
		if err != nil {
			return "", err
		}
		l := int(buf[0])
		_, err = io.ReadFull(conn, buf[:l])
		if err != nil {
			return "", err
		}
		host = string(buf[:l])

	default:
		return "", errors.New("unsupported atyp")
	}

	_, err = io.ReadFull(conn, buf[:2])
	if err != nil {
		return "", err
	}

	port := binary.BigEndian.Uint16(buf[:2])

	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, _ = conn.Write(reply)

	return fmt.Sprintf("%s:%d", host, port), nil
}

func socks5Dial(proxyAddr, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		conn.Close()
		return nil, err
	}

	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	if err != nil || buf[1] != 0x00 {
		conn.Close()
		return nil, errors.New("auth fail")
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}

	portNum, _ := strconv.Atoi(portStr)

	req := []byte{0x05, 0x01, 0x00}

	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(portNum))
	req = append(req, pb...)

	_, err = conn.Write(req)
	if err != nil {
		conn.Close()
		return nil, err
	}

	_, err = io.ReadFull(conn, make([]byte, 10))
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}
