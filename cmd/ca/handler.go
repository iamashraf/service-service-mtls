package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	CSRPEM string   `json:"csr_pem"`
}

// enrollResp is the JSON reply of POST /enroll.
type enrollResp struct {
	CertPEM string `json:"cert_pem"`
	CAPEM   string `json:"ca_pem"`
}

// NewHandler returns the CA service routes: POST /enroll and GET /healthz.
// secrets maps each enrollable name to its secret (header X-Enroll-Secret); a name not in the map is refused.
// ca_pem is always the demo CA, so rogue-issued certs fail to verify against it.
func NewHandler(demo, rogue *pki.CA, secrets map[string]string, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /enroll", func(w http.ResponseWriter, r *http.Request) {
		enroll(w, r, demo, rogue, secrets, now)
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

// forbidden replies 403. The same reply covers a missing, wrong and unknown-name secret.
func forbidden(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "enroll refused"})
}

// allowed reports whether the X-Enroll-Secret header matches the secret for name.
func allowed(secrets map[string]string, name, got string) bool {
	want, ok := secrets[name]
	return ok && subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// csrKey parses the CSR, checks its signature (proof the requester holds the private key)
// and returns the public key. Only P-256 keys are accepted. The CSR's own subject and SANs are ignored.
func csrKey(csrPEM string) (*ecdsa.PublicKey, bool) {
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, false
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, false
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	return pub, ok && pub.Curve == elliptic.P256()
}

// enroll checks the enrollment secret, validates the request strictly, then signs the CSR's public key.
// The CA never sees the private key. The secret only keeps out callers who merely reach the CA:
// a service that holds a secret can still enroll as that name.
func enroll(w http.ResponseWriter, r *http.Request, demo, rogue *pki.CA, secrets map[string]string, now func() time.Time) {
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
	if !allowed(secrets, req.Name, r.Header.Get("X-Enroll-Secret")) {
		forbidden(w)
		return
	}
	if len(req.DNS) > 10 {
		badRequest(w, "too many dns names")
		return
	}
	for _, d := range req.DNS {
		if !nameRe.MatchString(d) { // same rule as name: no wildcards, no odd chars
			badRequest(w, "invalid dns")
			return
		}
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
	pub, ok := csrKey(req.CSRPEM)
	if !ok {
		badRequest(w, "invalid csr")
		return
	}
	t := now()
	certPEM, err := issuer.Issue(req.Name, dns, eku, t.Add(-time.Minute), t.Add(24*time.Hour), pub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "issue failed"})
		return
	}
	writeJSON(w, http.StatusOK, enrollResp{string(certPEM), string(demo.PEM())})
}
