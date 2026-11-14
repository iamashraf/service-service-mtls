# Tutorial: build service-to-service AuthN and AuthZ with mTLS

## What you will build

Three services that prove who a caller is and what it may do. A Go mock CA hands out certs. A FastAPI server checks the client cert, then issues a token bound to it. A Java client runs seven checks and exits 0 only if all pass.

You will run the demo, then read each piece in the order a request meets it. Each step links to the code and to the standard behind it. For the full reasoning, see [guide.md](guide.md).

- AuthN (authentication) is who you are. The client cert answers it.
- AuthZ (authorization) is what you may do. The token scope answers it.

## Before you start

You need `podman` with `podman compose`. Nothing else.

```sh
podman compose up --build --exit-code-from client
```

Read the table the client prints. Every row must say `yes` in the MATCH column. Then clean up:

```sh
podman compose down -v
```

Each section below explains one row of that table.

## Step 1: Identity with mTLS

In normal TLS only the server shows a cert. In mutual TLS (mTLS) the client shows one too. The server accepts the connection only if the client cert comes from a CA it trusts.

The API sets `CERT_REQUIRED` and a TLS 1.3 minimum. A client with no cert, or a cert from another CA, never reaches the app code.

- Code: [api/app/__main__.py](../api/app/__main__.py), [api/app/tls.py](../api/app/tls.py)
- Standard: [RFC 8446, TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)

## Step 2: Get certs from the mock CA

The Go CA is a small HTTP service. A service calls `POST /enroll` with a name and a kind (`server` or `client`). The reply holds a cert, a private key and the CA cert.

```json
{"name": "java-writer", "kind": "client", "dns": [], "issuer": "demo"}
```

The cert's key usage matches the kind, so a client cert cannot act as a server. The `issuer: "rogue"` option signs with a second CA. Scenario 4 uses it.

This is a shortcut. A real CA takes a certificate signing request (CSR), so the private key never leaves the service. It also checks who is asking.

- Code: [cmd/ca/handler.go](../cmd/ca/handler.go), [internal/pki/pki.go](../internal/pki/pki.go)
- Standard: [RFC 2986, CSR](https://www.rfc-editor.org/rfc/rfc2986)

## Step 3: Read the peer cert in FastAPI

The app needs the client cert to bind a token to it. Python ASGI servers verify the cert but do not hand it to the app.

`PeerCertTCPServer` fixes this. After the handshake it copies the peer cert into a `ContextVar`. Handlers call `peer_identity()` to read it. Handlers must be `async def`, because a threadpool worker would not see the variable.

This relies on Hypercorn internals, so we pin the version. A test runs concurrent connections and checks that no cert leaks between them.

- Code: [api/app/tls.py](../api/app/tls.py), [test_app_tls.py](../api/tests/test_app_tls.py)
- Docs: [ASGI TLS extension](https://asgi.readthedocs.io/en/latest/extensions.html#tls-extension), [Hypercorn](https://hypercorn.readthedocs.io/)

## Step 4: Bind a token to the cert

The API signs an ES256 JWT (a signed token). It carries a `cnf` claim with the SHA-256 thumbprint of the client cert.

```json
{"sub": "java-writer", "aud": "api.demo", "scope": "orders:read orders:write",
 "cnf": {"x5t#S256": "<base64url SHA-256 of the cert DER>"}}
```

On every call the server hashes the cert from the connection and compares it with `cnf`. The compare is constant-time. A stolen token fails on any other cert.

- Code: [api/app/binding.py](../api/app/binding.py), [api/app/tokens.py](../api/app/tokens.py)
- Standards: [RFC 8705, certificate-bound tokens](https://www.rfc-editor.org/rfc/rfc8705), [RFC 7519, JWT](https://www.rfc-editor.org/rfc/rfc7519)
- Library: [PyJWT](https://pyjwt.readthedocs.io/)

## Step 5: Authorize with scopes

Scopes never come from the request. The server looks up the cert CN in a policy table.

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
| Thumbprint matches | `thumbprint_mismatch` | 401 |
| Scope allows the call | `insufficient_scope` | 403 |

401 means identity or binding failed. 403 means the identity is known but the action is not allowed.

- Code: [api/app/policy.py](../api/app/policy.py), [api/app/guard.py](../api/app/guard.py), [api/app/main.py](../api/app/main.py)
- Standard: [RFC 9110, HTTP status codes](https://www.rfc-editor.org/rfc/rfc9110#name-status-codes)

## Step 6: Write the Java client

The client builds a TLS context in memory. It loads the PEM key into a keystore, trusts only the CA from enrollment, and allows TLS 1.3 only. `HttpClient` then uses that context.

```java
SSLContext ctx = SSLContext.getInstance("TLSv1.3");
ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
```

The client keeps one context per identity, so the writer and the reader each present their own cert.

- Code: [Tls.java](../client/src/main/java/demo/Tls.java), [Enroller.java](../client/src/main/java/demo/Enroller.java), [Api.java](../client/src/main/java/demo/Api.java)
- Docs: [JSSE reference guide](https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html)

## Step 7: Walk the scenarios

The client runs these in [Main.java](../client/src/main/java/demo/Main.java).

| Scenario | Result | What it proves |
|---|---|---|
| 1 writer `GET` and `POST /orders` | 200, 201 | Valid cert and scope work |
| 2 reader `POST /orders` | 403 `insufficient_scope` | AuthN passed, AuthZ failed |
| 2 reader `GET /orders` | 200 | Read scope still works |
| 3 reader replays writer token | 401 `thumbprint_mismatch` | Binding blocks token theft |
| 4 rogue-CA cert | TLS handshake rejected | Unknown CA never reaches the app |
| 4 control: writer `GET` | 200 | The API was still up |

In scenario 4 the JDK does send the rogue cert. The server rejects it after the handshake. With TLS 1.3 the client sees this on its first read, as `Connection reset` or `EOF reached while reading`.

For real log lines per scenario, see [guide.md](guide.md#scenario-walk-through).

## Try it yourself

Changes 1 and 2 make the client exit 1. Undo each with `git checkout -- <file>` for that one file, then rerun to see it pass again.

1. **Remove a scope.** In [policy.py](../api/app/policy.py) delete `orders:write` from `java-writer`. Scenario 1 `POST` returns 403.
2. **Break the binding.** In [binding.py](../api/app/binding.py) make `matches` return `True`. Scenario 3 returns 200 instead of 401. This proves the check is what stops the replay.
3. **Watch the handshake.** Save this as `debug.yaml`, then run `podman compose -f compose.yaml -f debug.yaml up --build --exit-code-from client`. Search the output for `Produced client Certificate` to see each cert the client sends.

```yaml
services:
  client:
    environment:
      JAVA_TOOL_OPTIONS: "-Djavax.net.debug=ssl:handshake"
```

## Go further

This demo leaves out what a real system needs.

- **Rotation and revocation.** Certs last 24 hours and tokens 300 seconds. Nothing renews or revokes them.
- **Automated cert issuance.** See [ACME, RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) and [SPIFFE](https://spiffe.io/).
- **Key distribution.** The signing key lives in API memory. A real server publishes its public key, for example through JWKS ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)).
- **TLS-terminating proxies.** A proxy in front of the API hides the client cert and breaks the binding.

## Reference

| Topic | Code | Standard |
|---|---|---|
| mTLS | [tls.py](../api/app/tls.py) | [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) |
| Enrollment | [handler.go](../cmd/ca/handler.go) | [RFC 2986](https://www.rfc-editor.org/rfc/rfc2986) |
| Cert binding | [binding.py](../api/app/binding.py) | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) |
| Tokens | [tokens.py](../api/app/tokens.py) | [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) |
| Scopes | [guard.py](../api/app/guard.py) | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) |
| Java client | [Tls.java](../client/src/main/java/demo/Tls.java) | [JSSE](https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html) |
