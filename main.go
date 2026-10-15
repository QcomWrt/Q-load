//Q-load
// main.go
package main

import (
	"fmt"
	"os"

	// Import sub-package balance dari modul q-load
	"github.com/QcomWrt/Q-load/balance"
)

func main() {
	lport, tunnels := parseArgs()

	if lport == "" || len(tunnels) == 0 {
		fmt.Println("Usage:")
		fmt.Println("  q-load -lport 7777 -tunnel 127.0.0.1:1080 127.0.0.1:1081")
		os.Exit(1)
	}

	// Panggil fungsi Start dari package balance
	balance.Start(lport, tunnels)
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