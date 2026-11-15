# Tutorial: build service-to-service AuthN and AuthZ with mTLS

## What you will build

Four services that prove who a caller is and what it may do. A Go mock CA hands out certs. A FastAPI auth server checks the client cert, then issues a token bound to it. A FastAPI API serves REST and gRPC and checks that token. A Java client runs nine scenario groups and exits 0 only if all pass.

You will run the demo, then read each piece in the order a request meets it. Each step links to the code and to the standard behind it. For the full reasoning, see [guide.md](guide.md).

- AuthN (authentication) is who you are. The client cert answers it.
- AuthZ (authorization) is what you may do. The token scope answers it.

## Before you start

You need `podman` with `podman compose`, and a `.env.local` with the enrollment secrets. The [README](../README.md#see-it-in-2-minutes) shows sample values.

```sh
podman compose --env-file .env.local up --build --exit-code-from client
```

Read the table the client prints. It has 31 rows. Every row must say `yes` in the MATCH column. Then clean up:

```sh
podman compose --env-file .env.local down -v
```

Each section below explains one row of that table.

## Step 1: Identity with mTLS

In normal TLS only the server shows a cert. In mutual TLS (mTLS) the client shows one too. The server accepts the connection only if the client cert comes from a CA it trusts.

The auth server and the REST API set `CERT_REQUIRED` and a TLS 1.3 minimum. A client with no cert, or a cert from another CA, never reaches the app code. The gRPC port also requires a client cert but accepts TLS 1.2 (see [guide.md](guide.md#grpc-still-accepts-tls-12)).

- Code: [api/app/boot.py](../api/app/boot.py), [api/app/tls.py](../api/app/tls.py)
- Standard: [RFC 8446, TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)

## Step 2: Get certs from the mock CA

The Go CA is a small HTTP service. A service calls `POST /enroll` with a name and a kind (`server` or `client`). The service makes its own key and sends a CSR (certificate signing request) with an enrollment secret. The reply holds a cert and the CA cert. The private key never leaves the service.

```json
{"name": "java-writer", "kind": "client", "dns": [], "issuer": "demo", "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----..."}
```

The secret goes in the `X-Enroll-Secret` header. The CA refuses with 403 when it is missing, wrong or not set for that name. It takes the name from the JSON, not from the CSR.

The cert's key usage matches the kind, so a client cert cannot act as a server. The `issuer: "rogue"` option signs with a second CA. Scenario 4 uses it. Auth and api enroll as kind `both`, because each is a TLS server and the api is also a TLS client when it fetches the JWKS.

This is a shortcut. A real CA takes a certificate signing request (CSR), so the private key never leaves the service. It also checks who is asking.

- Code: [cmd/ca/handler.go](../cmd/ca/handler.go), [internal/pki/pki.go](../internal/pki/pki.go)
- Standard: [RFC 2986, CSR](https://www.rfc-editor.org/rfc/rfc2986)

## Step 3: Read the peer cert in FastAPI

The app needs the client cert to bind a token to it. Python ASGI servers verify the cert but do not hand it to the app.

`PeerCertTCPServer` fixes this. After the handshake it copies the peer cert into a `ContextVar`. Handlers call `peer_identity()` to read it.

This relies on Hypercorn internals, so we pin the version. A test runs concurrent connections and checks that no cert leaks between them.

- Code: [api/app/tls.py](../api/app/tls.py), [test_app_tls.py](../api/tests/test_app_tls.py)
- Docs: [ASGI TLS extension](https://asgi.readthedocs.io/en/latest/extensions.html#tls-extension), [Hypercorn](https://hypercorn.readthedocs.io/)

## Step 4: Bind a token to the cert

The auth server signs an ES256 JWT (a signed token). It carries a `cnf` claim with the SHA-256 thumbprint of the client cert.

```json
{"sub": "java-writer", "aud": "api.demo", "scope": "orders:read orders:write",
 "cnf": {"x5t#S256": "<base64url SHA-256 of the cert DER>"}}
```

On every call the API hashes the cert from the connection and compares it with `cnf`. The compare is constant-time, which is hygiene only since the thumbprint is not secret. A stolen token fails on any other cert.

- Code: [api/app/binding.py](../api/app/binding.py), [api/app/tokens.py](../api/app/tokens.py), [api/app/auth.py](../api/app/auth.py)
- Standards: [RFC 8705, certificate-bound tokens](https://www.rfc-editor.org/rfc/rfc8705), [RFC 7519, JWT](https://www.rfc-editor.org/rfc/rfc7519)
- Library: [PyJWT](https://pyjwt.readthedocs.io/)

## Step 5: Authorize with scopes

Scopes never come from the request. The auth server looks up the cert CN in a policy table.

| CN | Scopes |
|---|---|
| `java-writer` | `orders:read orders:write` |
| `java-reader` | `orders:read` |

On `/orders` the checks run in a fixed order. The first failure ends the request.

| Check | Reason | Status |
|---|---|---|
| Peer cert present | `no_client_cert` | 401 |
| Bearer token parses | `malformed` | 401 |
| Signature and expiry | `bad_signature`, `expired` | 401 |
| Audience and issuer | `bad_audience`, `bad_issuer` | 401 |
| `cnf` present | `no_cnf` | 401 |
| Thumbprint matches (Bearer) or DPoP proof valid | `thumbprint_mismatch`, `dpop_*` | 401 |
| Scope allows the call | `insufficient_scope` | 403 |

401 means identity or binding failed. 403 means the identity is known but the action is not allowed.

- Code: [api/app/policy.py](../api/app/policy.py), [api/app/guard.py](../api/app/guard.py), [api/app/main.py](../api/app/main.py)
- Standard: [RFC 9110, HTTP status codes](https://www.rfc-editor.org/rfc/rfc9110#name-status-codes)

## Step 6: Publish keys with a JWKS

The API does not hold a signing key. The auth server publishes its public keys at `/.well-known/jwks.json`. Each token carries a `kid` header, and the API picks the key by `kid`.

The API fetches the set over mTLS with its own cert. It caches keys for 300 seconds and refetches on an unknown `kid`, at most every 10 seconds. An unknown `kid` is `bad_signature`.

- Code: [api/app/keys.py](../api/app/keys.py), [api/app/jwks.py](../api/app/jwks.py), [api/app/tokens.py](../api/app/tokens.py)
- Standards: [RFC 7517, JWK and JWKS](https://www.rfc-editor.org/rfc/rfc7517), [RFC 8414, server metadata](https://www.rfc-editor.org/rfc/rfc8414)

## Step 7: Narrow a token with token exchange

A client can trade a token for one with fewer scopes. The auth server verifies the subject token, checks that its `cnf` matches the cert on this connection, then checks the audience and the scope. The new token keeps the same `cnf`.

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<token>&audience=api.demo&scope=orders:read
```

- Code: [api/app/exchange.py](../api/app/exchange.py), [api/app/auth.py](../api/app/auth.py)
- Standard: [RFC 8693, token exchange](https://www.rfc-editor.org/rfc/rfc8693)

## Step 8: Serve gRPC with the same checks

The API also serves an `Orders` gRPC service on port 9443. It reads the client cert from the gRPC auth context and calls the same `guard.authorize` as REST. 401-type failures become `UNAUTHENTICATED`, and `insufficient_scope` becomes `PERMISSION_DENIED`.

The Java client fetches its own token over mTLS. The built-in gRPC STS client sends no client cert, so its token could not be bound ([why](guide.md#why-the-java-grpc-client-fetches-its-own-token)).

- Code: [api/app/grpc_server.py](../api/app/grpc_server.py), [proto/orders.proto](../api/proto/orders.proto), [TokenSource.java](../client/src/main/java/demo/TokenSource.java), [OrdersGrpc.java](../client/src/main/java/demo/OrdersGrpc.java)
- Docs: [gRPC authentication](https://grpc.io/docs/guides/auth/)

## Step 9: Bind a token to a key with DPoP

DPoP binds a token to a key the client holds. The token carries `cnf.jkt`, the thumbprint of that key. Each call adds a signed proof with the method (`htm`), the URL (`htu`), a hash of the token (`ath`) and a one-time `jti`.

The API rejects a proof from another key, for another URL or method, or a reused `jti`. It also refuses a DPoP token sent as Bearer.

- Code: [api/app/dpop.py](../api/app/dpop.py), [Dpop.java](../client/src/main/java/demo/Dpop.java)
- Standards: [RFC 9449, DPoP](https://www.rfc-editor.org/rfc/rfc9449), [RFC 7638, JWK thumbprint](https://www.rfc-editor.org/rfc/rfc7638)

## Step 10: Write the Java client

The client builds a TLS context in memory. It loads the PEM key into a keystore, trusts only the CA from enrollment, and allows TLS 1.3 only. `HttpClient` then uses that context.

```java
SSLContext ctx = SSLContext.getInstance("TLSv1.3");
ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
```

The client keeps one context per identity, so the writer and the reader each present their own cert.

- Code: [Tls.java](../client/src/main/java/demo/Tls.java), [Enroller.java](../client/src/main/java/demo/Enroller.java), [Api.java](../client/src/main/java/demo/Api.java)
- Docs: [JSSE reference guide](https://docs.oracle.com/en/java/javase/25/security/java-secure-socket-extension-jsse-reference-guide.html)

## Step 11: Walk the scenarios

The client runs these in [Main.java](../client/src/main/java/demo/Main.java).

| Scenario | Result | What it proves |
|---|---|---|
| 1 writer `GET` and `POST /orders` | 200, 201 | Valid cert and scope work |
| 2 reader `POST /orders` | 403 `insufficient_scope` | AuthN passed, AuthZ failed |
| 2 reader `GET /orders` | 200 | Read scope still works |
| 3 reader replays writer token | 401 `thumbprint_mismatch` | Binding blocks token theft |
| 4 rogue-CA cert | TLS handshake rejected | Unknown CA never reaches the app |
| 4 control: writer `GET` | 200 | The API was still up |
| 5 attacker enrolls as `java-writer`, no or wrong secret | 403 | CN means scopes, so the CA checks who asks |
| 6 forged token, key not in JWKS | 401 `bad_signature` | The API trusts only published keys |
| 7 writer exchanges down to `orders:read` | 200, then `GET` 200, `POST` 403 | Exchange narrows scope |
| 7 reader asks `orders:write` | 400 `invalid_scope` | Exchange cannot widen scope |
| 7 reader uses writer subject token | 400 `invalid_grant` `thumbprint_mismatch` | The subject token is bound too |
| 7 unknown audience | 400 `invalid_target` | Audience comes from policy |
| 8 gRPC writer `Add` and `List` | OK | Same checks over gRPC |
| 8 gRPC reader `Add` | `PERMISSION_DENIED` `insufficient_scope` | 403 maps to `PERMISSION_DENIED` |
| 8 gRPC reader replays writer token | `UNAUTHENTICATED` `thumbprint_mismatch` | Binding holds on gRPC |
| 8 gRPC rogue cert | `UNAVAILABLE`, handshake rejected | Unknown CA fails before the app |
| 9 DPoP `GET` and `POST` | 200, 201 | Valid proof works |
| 9 DPoP proof from other key | 401 `dpop_jkt_mismatch` | The proof must match the token key |
| 9 DPoP wrong `htu` or `htm` | 401 `dpop_htu`, `dpop_htm` | A proof fits one URL and method |
| 9 DPoP reused `jti` | 401 `dpop_replay` | A proof works once |
| 9 DPoP token as Bearer | 401 `dpop_required` | A DPoP token cannot skip its proof |

In scenario 4 (and the gRPC rogue row) the JDK does send the rogue cert. The server rejects it after the handshake. With TLS 1.3 the client sees this on its first read, as `Connection reset` or `EOF reached while reading`.

For real log lines per scenario, see [guide.md](guide.md#scenario-walk-through).

## Try it yourself

Changes 1 and 2 make the client exit 1. Undo each with `git checkout -- <file>` for that one file, then rerun to see it pass again.

1. **Remove a scope.** In [policy.py](../api/app/policy.py) delete `orders:write` from `java-writer`. Scenario 1 `POST` returns 403.
2. **Break the binding.** In [binding.py](../api/app/binding.py) make `matches` return `True`. Scenario 3 returns 200 instead of 401. This proves the check is what stops the replay.
3. **Watch the handshake.** Save this as `debug.yaml`, then run `podman compose --env-file .env.local -f compose.yaml -f debug.yaml up --build --exit-code-from client`. Search the output for `Produced client Certificate` to see each cert the client sends.

```yaml
services:
  client:
    environment:
      JAVA_TOOL_OPTIONS: "-Djavax.net.debug=ssl:handshake"
```

## Go further

This demo leaves out what a real system needs.

- **Identity in a SAN.** The API reads the CN. Modern practice puts identity in a SAN, for example a SPIFFE URI SAN.
- **Rotation and revocation.** Certs last 24 hours and tokens 300 seconds. Nothing renews or revokes certs. Auth signing keys rotate only through code.
- **gRPC TLS version.** grpcio cannot enforce TLS 1.3, so port 9443 accepts TLS 1.2.
- **DPoP nonce.** The server does not issue a nonce, and the `jti` cache is in memory.
- **Automated cert issuance.** See [ACME, RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) and [SPIFFE](https://spiffe.io/).
- **TLS-terminating proxies.** A proxy in front of the API hides the client cert and breaks the binding.

## Reference

| Topic | Code | Standard |
|---|---|---|
| mTLS | [tls.py](../api/app/tls.py) | [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) |
| Enrollment | [handler.go](../cmd/ca/handler.go) | [RFC 2986](https://www.rfc-editor.org/rfc/rfc2986) |
| Cert binding | [binding.py](../api/app/binding.py) | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) |
| Tokens | [tokens.py](../api/app/tokens.py) | [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) |
| JWKS | [jwks.py](../api/app/jwks.py) | [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) |
| Token exchange | [exchange.py](../api/app/exchange.py) | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) |
| DPoP | [dpop.py](../api/app/dpop.py) | [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449), [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) |
| gRPC | [grpc_server.py](../api/app/grpc_server.py) | [gRPC auth](https://grpc.io/docs/guides/auth/) |
| Scopes | [guard.py](../api/app/guard.py) | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) |
| Java client | [Tls.java](../client/src/main/java/demo/Tls.java) | [JSSE](https://docs.oracle.com/en/java/javase/25/security/java-secure-socket-extension-jsse-reference-guide.html) |
