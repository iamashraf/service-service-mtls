// Command ca writes the demo CA, certs and token signing keys into CERTS_DIR.
package main

import (
	"crypto/x509"
	"log"
	"os"
	"time"

	"mtlsdemo/internal/pki"
)

func main() {
	dir := os.Getenv("CERTS_DIR")
	if dir == "" {
		dir = "/certs"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	ca, err := pki.NewCA("demo-ca")
	if err != nil {
		log.Fatal(err)
	}
	rogue, err := pki.NewCA("rogue-ca") // never written to disk: servers must not trust it
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	write := func(name string, c, k []byte) {
		if err := pki.WriteFile(dir, name+".pem", c); err != nil {
			log.Fatal(err)
		}
		if err := pki.WriteFile(dir, name+".key", k); err != nil {
			log.Fatal(err)
		}
	}
	issue := func(issuer *pki.CA, name string, dns []string, eku x509.ExtKeyUsage, nb, na time.Time) {
		c, k, err := issuer.Issue(name, dns, eku, nb, na)
		if err != nil {
			log.Fatal(err)
		}
		write(name, c, k)
	}
	if err := pki.WriteFile(dir, "ca.pem", ca.PEM()); err != nil {
		log.Fatal(err)
	}
	for _, s := range []string{"auth.demo", "api.demo"} {
		issue(ca, s, []string{s}, x509.ExtKeyUsageServerAuth, now.Add(-time.Minute), now.Add(24*time.Hour))
	}
	for _, c := range []string{"client-a", "client-b"} {
		issue(ca, c, nil, x509.ExtKeyUsageClientAuth, now.Add(-time.Minute), now.Add(24*time.Hour))
	}
	issue(ca, "client-expired", nil, x509.ExtKeyUsageClientAuth, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	issue(rogue, "client-rogue", nil, x509.ExtKeyUsageClientAuth, now.Add(-time.Minute), now.Add(24*time.Hour))
	k, p, err := pki.NewSigningKey()
	if err != nil {
		log.Fatal(err)
	}
	if err := pki.WriteFile(dir, "signing.key", k); err != nil {
		log.Fatal(err)
	}
	if err := pki.WriteFile(dir, "signing.pub", p); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote certs to %s", dir)
}
