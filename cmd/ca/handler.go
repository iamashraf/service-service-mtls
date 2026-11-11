package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"mtlsdemo/internal/pki"
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// enrollReq is the JSON body of POST /enroll.
type enrollReq struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	DNS    []string `json:"dns"`
	Issuer string   `json:"issuer"`
}

// enrollResp is the JSON reply of POST /enroll.
type enrollResp struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
	CAPEM   string `json:"ca_pem"`
}

// NewHandler returns the CA service routes: POST /enroll and GET /healthz.
// ca_pem is always the demo CA, so rogue-issued certs fail to verify against it.
func NewHandler(demo, rogue *pki.CA, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /enroll", func(w http.ResponseWriter, r *http.Request) {
		enroll(w, r, demo, rogue, now)
	})
	return mux
}

// writeJSON writes v as a JSON reply with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// badRequest replies 400 with {"error": msg}. No cert is ever issued on this path.
func badRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
}

// enroll validates the request strictly, then issues a cert and key.
// Demo shortcut: unauthenticated and returns the private key; a real CA takes a CSR.
func enroll(w http.ResponseWriter, r *http.Request, demo, rogue *pki.CA, now func() time.Time) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10) // cap input so a huge body cannot eat memory
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req enrollReq
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			badRequest(w, "body too large")
		} else {
			badRequest(w, "invalid json")
		}
		return
	}
	if !nameRe.MatchString(req.Name) {
		badRequest(w, "invalid name")
		return
	}
	issuer := demo
	switch req.Issuer {
	case "", "demo":
	case "rogue":
		issuer = rogue
	default:
		badRequest(w, "unknown issuer")
		return
	}
	var eku x509.ExtKeyUsage
	var dns []string
	switch req.Kind {
	case "server":
		if len(req.DNS) == 0 {
			badRequest(w, "dns required for server")
			return
		}
		eku, dns = x509.ExtKeyUsageServerAuth, req.DNS
	case "client":
		eku = x509.ExtKeyUsageClientAuth
	default:
		badRequest(w, "unknown kind")
		return
	}
	t := now()
	certPEM, keyPEM, err := issuer.Issue(req.Name, dns, eku, t.Add(-time.Minute), t.Add(24*time.Hour))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "issue failed"})
		return
	}
	writeJSON(w, http.StatusOK, enrollResp{string(certPEM), string(keyPEM), string(demo.PEM())})
}
