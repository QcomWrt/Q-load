package balance

import (
	"errors"
	"sync"
)

// Control memungkinkan pemanggil mengatur status aktif backend saat Q-load berjalan.
// Q-load tidak menentukan status ini sendiri; pemanggil yang memutuskan.
type Control struct {
	mu sync.Mutex
	lb *LoadBalancer
}

// SetAlive menandai backend dengan alamat addr aktif atau tidak.
// Backend yang tidak aktif dilewati saat memilih backend, tetapi tetap ada
// di daftar sehingga bisa diaktifkan lagi tanpa restart.
func (c *Control) SetAlive(addr string, alive bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lb == nil {
		return errors.New("Q-load belum berjalan")
	}
	for _, b := range c.lb.backends {
		if b.Addr == addr {
			b.alive.Store(alive)
			return nil
		}
	}
	return errors.New("backend tidak ditemukan: " + addr)
}

func (c *Control) attach(lb *LoadBalancer) {
	c.mu.Lock()
	c.lb = lb
	c.mu.Unlock()
}

func (c *Control) detach() {
	c.mu.Lock()
	c.lb = nil
	c.mu.Unlock()
}
