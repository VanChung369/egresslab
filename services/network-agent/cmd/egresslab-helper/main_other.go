//go:build !linux

package main

import "log"

func main() {
	log.Fatal("egresslab-helper runs only on Linux; use Ubuntu 22.04 in WSL2")
}
