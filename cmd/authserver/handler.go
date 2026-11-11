package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"mtlsdemo/internal/binding"
	"mtlsdemo/internal/jwt"
)

// ttl is the access token lifetime in seconds.
const ttl = 300 // seconds

// NewHandler returns a handler for POST /token. It issues a JWT bound to the
// thumbprint of the client cert on the TLS connection, never one named in the request.
// now is injectable so tests control exp.
func NewHandler(key *ecdsa.PrivateKey, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// A nil cert would panic in Thumbprint, so check before use.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			log.Printf("cn=%q thumb=- decision=deny reason=no_client_cert", "-")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "no_client_cert"})
			return
		}
		// The cert comes from the verified TLS connection, never from the request body:
		// the client cannot ask for a token bound to someone else's cert.
		cert := r.TLS.PeerCertificates[0]
		thumb := binding.Thumbprint(cert)
		tok, err := jwt.Sign(jwt.Claims{
			Iss: "https://auth.demo",
			Sub: cert.Subject.CommonName,
			Aud: "api.demo",
			Exp: now().Unix() + ttl,
			Cnf: &jwt.Cnf{X5tS256: thumb}, // binds the token to this cert
		}, key)
		if err != nil {
			log.Printf("cn=%q thumb=%.8s decision=error reason=sign_failed", cert.Subject.CommonName, thumb)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("cn=%q thumb=%.8s decision=allow reason=ok", cert.Subject.CommonName, thumb)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": ttl})
	})
	return mux
}
