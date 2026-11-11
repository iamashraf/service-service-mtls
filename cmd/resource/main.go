// Command resource serves GET /data over mTLS on :8443 to callers holding a bound token.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"mtlsdemo/internal/pki"
)

// main loads the certs from CERTS_DIR (default /certs) and serves until it fails.
func main() {
	dir := os.Getenv("CERTS_DIR")
	if dir == "" {
		dir = "/certs"
	}
	tlsCfg, err := pki.LoadServerTLS(dir, "api.demo")
	if err != nil {
		log.Fatal(err)
	}
	pub, err := pki.LoadSigningPub(dir)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr:      ":8443",
		Handler:   NewHandler(pub, "api.demo", time.Now),
		TLSConfig: tlsCfg,
		ErrorLog:  log.Default(), // handshake failures (no/bad client cert) land here
	}
	log.Println("resource server on :8443")
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
