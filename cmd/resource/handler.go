package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"mtlsdemo/internal/binding"
	"mtlsdemo/internal/jwt"
)

// NewHandler serves GET /data. now is injectable so tests control expiry.
func NewHandler(pub *ecdsa.PublicKey, aud string, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		cn, thumb := "-", "-"
		deny := func(reason string) {
			// %q on cn so a CN holding a newline cannot forge a log line. The token is never logged.
			log.Printf("cn=%q thumb=%.8s decision=deny reason=%s", cn, thumb, reason)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": reason})
		}
		// A nil cert would panic in Thumbprint/Match, so check before use.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			deny("no_client_cert")
			return
		}
		cert := r.TLS.PeerCertificates[0]
		cn, thumb = cert.Subject.CommonName, binding.Thumbprint(cert)

		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			deny("malformed")
			return
		}
		// Signature and expiry are checked first: claims from an unsigned token mean nothing.
		c, err := jwt.Verify(raw, pub, now())
		switch {
		case errors.Is(err, jwt.ErrBadSignature):
			deny("bad_signature")
			return
		case errors.Is(err, jwt.ErrExpired):
			deny("expired")
			return
		case err != nil:
			deny("malformed")
			return
		}
		// Without aud, a token minted for another service would work here.
		if c.Aud != aud {
			deny("bad_audience")
			return
		}
		// A token with no cnf is a plain bearer token: reject, never skip the binding check.
		if c.Cnf == nil || c.Cnf.X5tS256 == "" {
			deny("no_cnf")
			return
		}
		// The point of the demo: a stolen token fails here because the thief's connection has another cert.
		if !binding.Match(c.Cnf.X5tS256, cert) {
			deny("thumbprint_mismatch")
			return
		}
		log.Printf("cn=%q thumb=%.8s decision=allow reason=ok", cn, thumb)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"data": "hello " + c.Sub})
	})
	return mux
}
