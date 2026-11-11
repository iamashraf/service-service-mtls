// Command ca runs the demo HTTP certificate authority on :8080.
package main

import (
	"log"
	"net/http"
	"time"

	"mtlsdemo/internal/pki"
)

// main builds the demo and rogue CAs in memory and serves /enroll.
// The rogue CA exists only in memory, so no server can ever be configured to trust it.
func main() {
	demo, err := pki.NewCA("demo-ca")
	if err != nil {
		log.Fatal(err)
	}
	rogue, err := pki.NewCA("rogue-ca")
	if err != nil {
		log.Fatal(err)
	}
	log.Print("ca listening on :8080")
	srv := &http.Server{Addr: ":8080", Handler: NewHandler(demo, rogue, time.Now), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
