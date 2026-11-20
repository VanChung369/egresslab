package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/VanChung369/egresslab/services/controller/internal/control"
)

func main() {
	address := flag.String("listen", "127.0.0.1:8787", "Loopback HTTP control API address")
	flag.Parse()
	host, _, err := net.SplitHostPort(*address)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		log.Fatal("control API must listen on loopback only")
	}
	root := os.Getenv("EGRESSLAB_DATA_DIR")
	if root == "" {
		config, err := os.UserConfigDir()
		if err != nil {
			log.Fatal(err)
		}
		root = filepath.Join(config, "EgressLab")
	}
	store, err := control.NewStore(filepath.Join(root, "state.json"))
	if err != nil {
		log.Fatal(err)
	}
	api := &control.API{Store: store, Started: time.Now()}
	server := &http.Server{
		Addr: *address, Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second,
	}
	log.Printf("EgressLab controller %s listening at http://%s", control.Version, *address)
	log.Printf("Mode: control-plane-only (no live VPN or proxy routing)")
	log.Fatal(server.ListenAndServe())
}
