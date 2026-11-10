# Learnings

## Task 1: certificate thumbprint

`x5t#S256` is the SHA-256 of a certificate's DER bytes, base64url encoded with no padding. It is 43 characters.
We hash the DER bytes because they are the one canonical form. Re-encoding the PEM or reading fields can differ, the raw bytes cannot.
The thumbprint names one exact certificate. It says nothing about who the owner is. A CN is just text inside the cert.
Gotcha: base64url with padding (`=`) or std base64 (`+`, `/`) gives a different string and the match silently fails.

## Task 2: ES256 JWT

`Verify` checks the header says `ES256` before it looks at the signature. A token that picks its own algorithm (`none`, or `HS256` keyed with the public key) is how alg confusion attacks work.
JOSE signatures are raw `r||s`, 64 bytes, base64url. Go's `ecdsa.SignASN1` gives DER instead, and a DER signature fails in every other JWT tool.
Each of r and s must be left-padded to 32 bytes. `big.Int.Bytes()` drops leading zeros and breaks about 1 in 128 signatures.
The signature is checked before the claims are parsed or the expiry is read.
This is a demo. Use a maintained JWT library in real code.

## Task 3: certificates and TLS config

A client cert fails in three ways: the issuer is not trusted (rogue CA), the cert is outside its dates (expired), or its key usage is wrong (a server-only cert used as a client cert). The demo makes the first two on purpose.
A SAN (subject alternative name) is the hostname list inside a server cert. Go checks the SAN and ignores the CN, so `api.demo` must be a DNS SAN or clients reject it.
The server uses `RequireAndVerifyClientCert`. Plain `RequireAnyClientCert` accepts any cert and skips the CA check.
TLS 1.3 only: it drops weak legacy ciphers and encrypts the client cert during the handshake.
Gotcha: `os.WriteFile` keeps the old file mode on overwrite, so `WriteFile` calls `Chmod` to keep keys at 0600.
