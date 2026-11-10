package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"mtlsdemo/internal/pki"
)

func main() {
	dir := os.Getenv("CERTS_DIR")
	if dir == "" {
		dir = "/certs"
	}
	tlsCfg, err := pki.LoadServerTLS(dir, "auth.demo")
	if err != nil {
		log.Fatal(err)
	}
	key, err := pki.LoadSigningKey(dir)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr:      ":8443",
		Handler:   NewHandler(key, time.Now),
		TLSConfig: tlsCfg,
		ErrorLog:  log.Default(), // handshake failures (no/bad client cert) land here
	}
	log.Println("auth server on :8443")
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
