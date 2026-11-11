// Package jwt is a hand-rolled ES256 JWT for the demo. Not a library to reuse.
package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

// Cnf is the RFC 8705 confirmation claim. X5tS256 is the thumbprint of the bound client cert.
type Cnf struct {
	X5tS256 string `json:"x5t#S256"`
}

// Claims is the token payload. Cnf is set when the token is bound to a client cert.
type Claims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Cnf *Cnf   `json:"cnf,omitempty"`
}

// Sentinel errors returned by Verify. Callers match them with errors.Is.
var (
	ErrMalformed    = errors.New("malformed token")
	ErrBadSignature = errors.New("bad signature")
	ErrExpired      = errors.New("token expired")
)

// header is the fixed JOSE header. size is the byte length of one P-256 signature coordinate.
const (
	header = `{"alg":"ES256","typ":"JWT"}`
	size   = 32 // P-256 coordinate size in bytes
)

// enc is base64url without padding, as JWT requires.
var enc = base64.RawURLEncoding

// Sign returns c as a compact ES256 JWT signed with key.
func Sign(c Claims, key *ecdsa.PrivateKey) (string, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	input := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString(body)
	h := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return "", err
	}
	// JOSE wants raw r||s, each left-padded to 32 bytes. Not ASN.1 DER.
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return input + "." + enc.EncodeToString(sig), nil
}

// Verify returns the claims of token if it is a valid, unexpired ES256 JWT for pub.
// It pins the algorithm and checks the signature before parsing the claims.
// It does not check iss, aud or cnf. The caller must.
func Verify(token string, pub *ecdsa.PublicKey, now time.Time) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformed
	}
	rawHdr, err := enc.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	// Pin the algorithm before touching the signature: stops alg=none and alg confusion.
	if json.Unmarshal(rawHdr, &hdr) != nil || hdr.Alg != "ES256" {
		return Claims{}, ErrMalformed
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil || len(sig) != 2*size {
		return Claims{}, ErrMalformed
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
	// Check the signature before trusting or even parsing the payload.
	if !ecdsa.Verify(pub, h[:], r, s) {
		return Claims{}, ErrBadSignature
	}
	rawBody, err := enc.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var c Claims
	if json.Unmarshal(rawBody, &c) != nil {
		return Claims{}, ErrMalformed
	}
	if now.Unix() > c.Exp {
		return Claims{}, ErrExpired
	}
	return c, nil
}
