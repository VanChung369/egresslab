//go:build !linux

package main

import "log"

func main() {
	log.Fatal("egresslab-proxy-dial runs only on Linux, inside a lab namespace started by the helper")
}
