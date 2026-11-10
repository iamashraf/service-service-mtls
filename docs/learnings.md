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

## Task 4: auth server

The auth server binds the token to the cert it saw on the TLS connection (`r.TLS.PeerCertificates[0]`). The TLS handshake already proved the client holds that cert's private key.
The client never sends a thumbprint. If it could, it could ask for a token bound to someone else's cert, and the binding would prove nothing.
`cnf.x5t#S256` is the SHA-256 of the cert DER, so the API can recompute it from its own connection.
Gotcha: with `RequireAndVerifyClientCert` a client with no cert never reaches the handler. The `no_client_cert` 401 is a guard for direct calls, and the handshake error shows only in `http.Server.ErrorLog`.

## Task 5: resource server

A valid signature and valid claims are not enough. The connection must also present the cert the token is bound to.
The check order is: cert present, token parses, signature and expiry, audience, `cnf` present, thumbprint match.
A token with no `cnf` is rejected. Skipping the binding check would turn it back into a plain bearer token.
Gotcha: if a proxy terminates TLS, the resource server never sees the client cert, so it cannot check the binding.
Either pass the cert on (and trust only that proxy) or do the check at the proxy.

## Task 6: end-to-end with podman compose

Gotcha: under TLS 1.3 the client finishes its handshake before the server checks the client cert. The rejection (`expired certificate`, `certificate required`) arrives on the first read, so `verify` treats any error from `client.Do` as the rejection.
Gotcha: `--exit-code-from` implies abort-on-container-exit, so a one-shot `ca` that exits with 0 still stops the whole stack. `service_completed_successfully` therefore failed under podman compose (docker-compose v5.6.1) as a race.
Workaround: `ca` writes the certs, creates `/certs/.ready` and stays alive. A healthcheck on that file and `service_healthy` replace `service_completed_successfully`.
Compose ordering teaches that "started" is not "ready". The servers need the certs before they start, so the dependency has to be on the certs existing.
Pitfall: the `certs` volume survives `down` without `-v`, so a stale `.ready` would make the healthcheck pass early. `ca` runs `rm -f /certs/.ready` first.
