// Package pki issues demo certificates and loads TLS configs from a cert dir.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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

// Issue signs a leaf cert. eku limits what the cert may be used for.
func (c *CA) Issue(cn string, dns []string, eku x509.ExtKeyUsage, notBefore, notAfter time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
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
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// NewSigningKey makes the token signing pair: PKCS8 private, PKIX public, both PEM.
func NewSigningKey() (keyPEM, pubPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	p, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: p}), nil
}

// WriteFile writes data to dir/name. Files ending in .key get mode 0600, others 0644.
func WriteFile(dir, name string, data []byte) error {
	mode := os.FileMode(0o644)
	if strings.HasSuffix(name, ".key") {
		mode = 0o600 // private keys readable by owner only
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, mode); err != nil {
		return err
	}
	return os.Chmod(p, mode) // WriteFile keeps the old mode when overwriting
}

// loadPool returns a cert pool holding the CA certificate in dir/ca.pem.
func loadPool(dir string) (*x509.CertPool, error) {
	b, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, errors.New("ca.pem has no certificate")
	}
	return p, nil
}

// LoadServerTLS returns a TLS 1.3 server config using dir/name.pem and dir/name.key.
// It requires a client cert signed by the CA in dir/ca.pem.
func LoadServerTLS(dir, name string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key"))
	if err != nil {
		return nil, err
	}
	pool, err := loadPool(dir)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // no cert or untrusted cert: handshake fails
		MinVersion:   tls.VersionTLS13,               // 1.3 encrypts the client cert in the handshake
	}, nil
}

// LoadClientTLS returns a TLS 1.3 client config that presents dir/name.pem.
// It trusts only the CA in dir/ca.pem and checks the server cert against serverName.
func LoadClientTLS(dir, name, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key"))
	if err != nil {
		return nil, err
	}
	pool, err := loadPool(dir)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName, // checked against the server cert SAN
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// readPEM returns the first PEM block of dir/name.
func readPEM(dir, name string) (*pem.Block, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New(name + ": no PEM block")
	}
	return blk, nil
}

// LoadSigningKey returns the ECDSA private key in dir/signing.key.
func LoadSigningKey(dir string) (*ecdsa.PrivateKey, error) {
	blk, err := readPEM(dir, "signing.key")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing.key is not ECDSA")
	}
	return ek, nil
}

// LoadSigningPub returns the ECDSA public key in dir/signing.pub.
func LoadSigningPub(dir string) (*ecdsa.PublicKey, error) {
	blk, err := readPEM(dir, "signing.pub")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("signing.pub is not ECDSA")
	}
	return ek, nil
}
