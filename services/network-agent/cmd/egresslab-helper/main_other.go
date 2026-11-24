//go:build !linux

package main

import "log"

func main() {
	log.Fatal("egresslab-helper runs only on Linux: a Linux host, WSL2 or a Linux VM such as Lima")
}
