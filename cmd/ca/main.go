// Command ca runs the demo HTTP certificate authority on :8080.
package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"mtlsdemo/internal/pki"
)

// secretsFromEnv parses ENROLL_SECRETS ("name=secret,name=secret"). Empty secrets are dropped.
func secretsFromEnv() map[string]string {
	m := map[string]string{}
	for _, kv := range strings.Split(os.Getenv("ENROLL_SECRETS"), ",") {
		if n, s, ok := strings.Cut(kv, "="); ok && n != "" && s != "" {
			m[n] = s
		}
	}
	return m
}

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
	srv := &http.Server{Addr: ":8080", Handler: NewHandler(demo, rogue, secretsFromEnv(), time.Now), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
