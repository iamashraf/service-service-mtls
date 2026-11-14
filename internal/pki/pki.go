// Package pki issues demo certificates.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// CA is a demo certificate authority: its certificate and signing key.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// serial returns a random 128-bit certificate serial number.
func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// NewCA returns a new self-signed P-256 CA named cn, valid for 24 hours.
func NewCA(cn string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true, // only a CA cert may sign leaves
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// PEM returns the CA certificate in PEM form.
func (c *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}

// Issue signs a leaf cert for the requester's public key; the CA never sees the private key.
// eku limits what the cert may be used for.
func (c *CA) Issue(cn string, dns []string, eku x509.ExtKeyUsage, notBefore, notAfter time.Time, pub *ecdsa.PublicKey) (certPEM []byte, err error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dns, // SANs: Go ignores CN when matching hostnames
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku}, // client vs server role is enforced by this
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, pub, c.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
