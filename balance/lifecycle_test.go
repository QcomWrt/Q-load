package balance

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestStartContextStopsOnCancel(t *testing.T) {
	// Cari port lokal yang tersedia.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- StartContext(ctx, strconv.Itoa(port), []string{
			"127.0.0.1:1",
		})
	}()

	// Tunggu sampai listener mulai aktif.
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(3 * time.Second)

	for {
		conn, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			break
		}

		if time.Now().After(deadline) {
			cancel()
			t.Fatal("Q-load listener tidak aktif dalam 3 detik")
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("StartContext mengembalikan error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("StartContext tidak berhenti setelah context dibatalkan")
	}

	// Pastikan listener tidak lagi menerima koneksi.
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatal("listener masih menerima koneksi setelah cancel")
	}
}

func TestStartContextClosesActiveClient(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- StartContext(ctx, strconv.Itoa(port), []string{
			"127.0.0.1:1",
		})
	}()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(3 * time.Second)

	var client net.Conn

	for time.Now().Before(deadline) {
		client, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if client == nil {
		t.Fatal("Q-load listener tidak aktif dalam 3 detik")
	}
	defer client.Close()

	// Kirim greeting SOCKS5 agar koneksi masuk ke proses handshake.
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("gagal mengirim greeting SOCKS5: %v", err)
	}

	// Server seharusnya membalas dengan metode autentikasi yang dipilih.
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("gagal membaca balasan SOCKS5: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("balasan SOCKS5 tidak sesuai: %v", reply)
	}
	_ = client.SetReadDeadline(time.Time{})

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("StartContext mengembalikan error: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("Q-load tidak berhenti setelah context dibatalkan")
	}

	// Setelah shutdown, koneksi klien harus sudah ditutup.
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, err = client.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("koneksi klien masih terbuka setelah shutdown")
	}
}
