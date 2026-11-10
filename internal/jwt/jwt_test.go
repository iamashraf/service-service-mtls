package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var now = time.Unix(1_700_000_000, 0)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func claims() Claims {
	return Claims{Iss: "auth.demo", Sub: "client-a", Aud: "api.demo", Exp: now.Add(5 * time.Minute).Unix(), Cnf: &Cnf{X5tS256: "abc"}}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestRoundTrip(t *testing.T) {
	k := newKey(t)
	tok, err := Sign(claims(), k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(tok, &k.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, claims()) {
		t.Fatalf("got %+v", got)
	}
}

func TestTamperedPayload(t *testing.T) {
	k := newKey(t)
	tok, _ := Sign(claims(), k)
	p := strings.Split(tok, ".")
	p[1] = b64(`{"iss":"auth.demo","sub":"evil","aud":"api.demo","exp":9999999999}`)
	if _, err := Verify(strings.Join(p, "."), &k.PublicKey, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestWrongKey(t *testing.T) {
	tok, _ := Sign(claims(), newKey(t))
	if _, err := Verify(tok, &newKey(t).PublicKey, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestExpired(t *testing.T) {
	k := newKey(t)
	tok, _ := Sign(claims(), k)
	if _, err := Verify(tok, &k.PublicKey, now.Add(10*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v", err)
	}
}

func TestBadAlg(t *testing.T) {
	k := newKey(t)
	body, _ := json.Marshal(claims())
	for _, alg := range []string{"none", "HS256"} {
		// Valid ES256 signature over the swapped header: only the alg check can reject it.
		input := b64(`{"alg":"`+alg+`","typ":"JWT"}`) + "." + base64.RawURLEncoding.EncodeToString(body)
		h := sha256.Sum256([]byte(input))
		r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		tok := input + "." + base64.RawURLEncoding.EncodeToString(sig)
		if _, err := Verify(tok, &k.PublicKey, now); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%s: got %v", alg, err)
		}
	}
}

func TestMalformed(t *testing.T) {
	k := newKey(t)
	for _, tok := range []string{"", "a.b", "a.b.c.d"} {
		if _, err := Verify(tok, &k.PublicKey, now); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%q: got %v", tok, err)
		}
	}
}

func TestSignatureLength(t *testing.T) {
	tok, _ := Sign(claims(), newKey(t))
	sig, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("len=%d err=%v", len(sig), err)
	}
}
