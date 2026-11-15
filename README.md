# service-service-mtls

**Demo only. Not for production.** A runnable demo of how services prove who they are (AuthN) and what they may do (AuthZ). Calls use mutual TLS (mTLS). A separate auth server issues short-lived tokens, and a resource server accepts them over REST and gRPC.

Tokens use one of two bindings. A certificate-bound token ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)) works only on the client cert it was issued to. A DPoP token ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) works only with a proof signed by the key it was issued to. A stolen token is useless without that cert or key.

One command starts a Go CA, an auth server, a resource server and a Java 25 client. The client runs nine groups of scenarios and exits 0 only if every one behaves as expected.

## What this demonstrates

| Skill | Where to see it |
|---|---|
| PKI and mutual TLS | [Go CA](cmd/ca/handler.go), [TLS 1.3 server setup](api/app/tls.py) |
| Certificate-bound tokens (RFC 8705) | [tokens](api/app/tokens.py), [thumbprint check](api/app/binding.py) |
| Signed keys and rotation (JWKS) | [key set](api/app/keys.py), [JWKS cache](api/app/jwks.py) |
| Token exchange ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)) | [exchange logic](api/app/exchange.py) |
| DPoP (RFC 9449) | [proof checks](api/app/dpop.py), [client](client/src/main/java/demo/Dpop.java) |
| gRPC with the same checks | [gRPC server](api/app/grpc_server.py), [proto](api/proto/orders.proto) |
| Authorization design | [policy table](api/app/policy.py), [ordered checks](api/app/guard.py) |
| Three languages in one system | Go, Python 3.14, Java 25 |
| Containers and tests | [compose.yaml](compose.yaml), four services, podman, 142 pytest tests |

## See it in 2 minutes

You need `podman` with `podman compose`.

Put the enrollment secrets in `.env.local` in the repo root. Git ignores it and no image build includes it. These values are samples. Use your own, for example from `openssl rand -hex 16`.

```sh
ENROLL_SECRET_WRITER=sample-writer-secret
ENROLL_SECRET_READER=sample-reader-secret
ENROLL_SECRET_ROGUE=sample-rogue-secret
ENROLL_SECRET_API=sample-api-secret
ENROLL_SECRET_AUTH=sample-auth-secret
```

| Variable | Used by | Enrolls as |
|---|---|---|
| `ENROLL_SECRET_WRITER` | ca, client | `java-writer` |
| `ENROLL_SECRET_READER` | ca, client | `java-reader` |
| `ENROLL_SECRET_ROGUE` | ca, client | `java-rogue` |
| `ENROLL_SECRET_API` | ca, api | `api.demo` (kind `both`) |
| `ENROLL_SECRET_AUTH` | ca, auth | `auth.demo` (kind `both`) |

Compose stops with an error if one is missing. Kind `both` means the cert works as a server cert and as a client cert, because api and auth call each other.

```sh
podman compose --env-file .env.local up --build --exit-code-from client
```

Real output from a run:

```text
SCENARIO                                 EXPECTED                                     MATCH  ACTUAL
1 writer GET /orders                     200                                          yes    200
1 writer POST /orders                    201                                          yes    201
2 reader POST /orders                    403 insufficient_scope                       yes    403 insufficient_scope
2 reader GET /orders                     200                                          yes    200
3 reader replays writer token            401 thumbprint_mismatch                      yes    401 thumbprint_mismatch
4 rogue cert                             TLS handshake rejected                       yes    java.io.IOException: EOF reached while reading
4 control: writer still served           200                                          yes    200
5 attacker enrolls, no secret            403 enroll refused                           yes    403
5 attacker enrolls, wrong secret         403 enroll refused                           yes    403
6 forged token, key not in JWKS          401 bad_signature                            yes    401 bad_signature
6 forged signature, real kid             401 bad_signature                            yes    401 bad_signature
7 writer exchanges down to orders:read   200                                          yes    200
7 narrowed token GET /orders             200                                          yes    200
7 narrowed token POST /orders            403 insufficient_scope                       yes    403 insufficient_scope
7 reader asks orders:write               400 invalid_scope scope_not_allowed          yes    400 invalid_scope scope_not_allowed
7 reader uses writer subject token       400 invalid_grant thumbprint_mismatch        yes    400 invalid_grant thumbprint_mismatch
7 unknown audience                       400 invalid_target audience_not_allowed      yes    400 invalid_target audience_not_allowed
8 grpc writer Add                        OK                                           yes    OK
8 grpc writer List                       OK                                           yes    OK
8 grpc reader Add                        PERMISSION_DENIED insufficient_scope         yes    PERMISSION_DENIED insufficient_scope
8 grpc reader List                       OK                                           yes    OK
8 grpc reader replays writer token       UNAUTHENTICATED thumbprint_mismatch          yes    UNAUTHENTICATED thumbprint_mismatch
8 grpc rogue cert                        TLS handshake rejected                       yes    UNAVAILABLE Network closed for unknown reason
8 grpc control: writer still served      OK                                           yes    OK
9 dpop GET /orders                       200                                          yes    200
9 dpop POST /orders                      201                                          yes    201
9 dpop proof from other key              401 dpop_jkt_mismatch                        yes    401 dpop_jkt_mismatch
9 dpop wrong htu                         401 dpop_htu                                 yes    401 dpop_htu
9 dpop wrong htm                         401 dpop_htm                                 yes    401 dpop_htm
9 dpop reused jti                        401 dpop_replay                              yes    401 dpop_replay
9 dpop token as Bearer                   401 dpop_required                            yes    401 dpop_required
```

Clean up with `podman compose --env-file .env.local down -v`.

## Architecture

The [interactive runtime architecture diagram](https://iamashraf.github.io/service-service-mtls/runtime-architecture.html) shows the services, the trust boundary and the request path.

| Service | Stack | Address | Job |
|---|---|---|---|
| ca | Go | `ca.demo:8080` | Issues certs at `POST /enroll` |
| auth | FastAPI on Hypercorn | `auth.demo:8443` | Requires a client cert. Issues tokens, does token exchange, serves the signing keys (JWKS) |
| api | FastAPI on Hypercorn, grpcio | `api.demo:8443` REST, `api.demo:9443` gRPC | Requires a client cert. Checks tokens on `/orders` and on the gRPC `Orders` service |
| client | Java 25 | none | Runs the scenarios and sets the exit code |

1. Each service enrolls with the CA and gets a cert.
2. The api fetches the public signing keys from `auth` over mTLS and caches them.
3. The client calls `POST /token` on `auth` over mTLS. `auth` signs an ES256 token that carries the client cert thumbprint, or the DPoP key thumbprint if the client sent a DPoP proof.
4. Optionally, the client exchanges that token for one with fewer scopes.
5. The client calls the api with the token, over REST or gRPC.
6. The api verifies the signature with the cached keys, then checks the binding and the scope.

## Design decisions

### Tokens and keys

- **Bind the token to the cert.** The token holds the cert thumbprint, so a copy sent over another connection fails with 401.
- **Scopes come from a server policy.** `auth` looks up the cert CN. Nothing in the `/token` request can raise a scope. The CA checks an enrollment secret per name, so whoever controls enrollment controls scopes.
- **Enroll with a CSR.** Each service makes its own key and sends only a certificate signing request. The private key never crosses the network, and the CA ignores the name inside the CSR.
- **401 and 403 mean different things.** 401 means identity or binding failed. 403 means the identity is known and the action is not allowed.
- **TLS 1.3 on REST.** Hypercorn allows 1.2 by default, so a `Config` subclass raises the floor. A test shows the server rejects a 1.2 client.
- **A pinned adapter for the peer cert.** ASGI servers verify client certs but do not pass them to the app. A small `TCPServer` subclass does, and a test checks that concurrent connections never see each other's cert.
- **Constant-time compare.** Good hygiene only. The thumbprint is not secret.

### JWKS

- **Separate signer and verifier.** `auth` holds the ES256 private key. The api holds only public keys, so a stolen api cannot mint tokens.
- **Keys are published, not shared.** Tokens carry a `kid`. The api fetches `/.well-known/jwks.json` over mTLS with its own cert, caches it for up to 300 s, and refetches at most every 10 s when it sees an unknown `kid`.
- **Rotation keeps two keys.** The old key stays in the set so tokens signed before a rotation still verify.
- **An unknown `kid` is `bad_signature`.** A token signed by a key outside the set (scenario 6) fails closed. The `alg` is pinned to ES256 before anything else.

### Token exchange

- **Narrow a token, never widen it.** The client posts a form to `/token` with the RFC 8693 grant, its token and a smaller scope. The new token keeps the same cert binding.
- **Errors are HTTP 400** with `error` and `error_description`.
- **Check order.** Client cert, grant type, subject token, thumbprint, audience, scope. The thumbprint check uses this connection's cert, so a reader cannot exchange the writer's token.

| Failure | Response |
|---|---|
| Subject token fails verification | `invalid_grant` with the reason code |
| Token bound to another cert | `invalid_grant thumbprint_mismatch` |
| Audience not in policy | `invalid_target` |
| Scope not a subset of subject token and policy | `invalid_scope` |

### gRPC

- **Same checks as REST.** The gRPC server calls the same `authorize` function with the token from the `authorization` metadata. Failures map to `UNAUTHENTICATED` (message is the reason) or `PERMISSION_DENIED insufficient_scope`.
- **The client fetches its own token.** A `TokenSource` calls `/token` over mTLS with the same identity as the channel. A `CallCredentials` attaches it and refreshes it 30 s before expiry.
- **The built-in STS client cannot bind.** It fetches the token with its own HTTP client, which has no way to present the channel's client cert (see [grpc-go issue 5099](https://github.com/grpc/grpc-go/issues/5099)). The token would be issued unbound or fail, so the demo does not use it.

### DPoP

- **One binding per token, never both.** A DPoP token has `cnf.jkt` and no cert thumbprint. Using it as Bearer fails with `dpop_required`. A cert-bound token sent as DPoP fails with `bearer_required`.
- **The client cert is still required.** mTLS authenticates the connection. DPoP only changes what the token is bound to.
- **`htu` comes from config.** The api compares the proof's `htu` with `API_PUBLIC_URL` plus the path. It never trusts the `Host` header.
- **Replay cache.** The api keeps each `jti` in memory for 120 s. A proof is checked for replay last, so a proof that fails any other check does not use up its `jti`.

## Container security

All four services run with the same limits. The [guide](guides/guide.md#container-hardening) gives the reason for each.

- They run as `nobody` (uid 65534), not root.
- The root filesystem is read-only. Only tmpfs mounts are writable: `/tmp`, `/var/tmp` and `/dev/shm`. `auth` and `api` write their cert files to `/tmp`.
- All Linux capabilities are dropped, and `no-new-privileges` is set.
- Start order: `ca`, then `auth`, then `api`, then `client`. Each waits for the healthcheck of the one before.
- The api healthcheck opens both TLS ports (8443 and 9443).
- Each build context is an allowlist, and `.env` files are excluded everywhere.

## Tests

- `go test ./...` covers the CA and cert issuing.
- `pytest` in `api/` runs 142 tests. They include live mTLS and gRPC handshakes, every rejection reason, forged and `alg: none` tokens, exchange errors and DPoP replay.
- `mvn test` in `client/` runs 21 Java unit tests.
- The client run is the end-to-end test. Breaking a check makes it exit 1.
- [CI](.github/workflows/ci.yml) runs the Go, Python and Java tests on every push.

## Known limits

- `/enroll` uses plain HTTP, and the enrollment secrets are random per machine in `.env.local`, not a real secret store. A real CA checks the platform identity of the caller, for example a Kubernetes service account token or SPIFFE attestation.
- The client container holds the `java-writer` secret, so a compromised client can still enroll as the writer.
- Identity is the cert CN. Modern practice uses a SAN, for example a SPIFFE URI SAN.
- The leaf and the CA are both valid for 24 hours. A stack left up for over 24 hours breaks.
- The apps trust the CA cert from the same call that enrolls them.
- Keys live in memory only. A restart rotates them, and there is no revocation.
- gRPC accepts TLS 1.2. grpcio cannot enforce a floor. The client cert is still required.
- `auth` serves JWKS only over mTLS. The api caches it up to 300 s, so a retired key still verifies until the cache expires.
- The DPoP `jti` cache is in memory and per process. Several replicas need a shared store.
- There is no DPoP server nonce.
- Exchange of DPoP tokens is not supported.
- DPoP tokens are not supported on gRPC.
- A TLS-terminating proxy in front of the api hides the client cert and breaks cert binding. DPoP is unaffected. The demo has no proxy profile, so this is not shown.

## Docs

- [guides/tutorial.md](guides/tutorial.md): step-by-step tutorial with links to the code and the standards
- [guides/guide.md](guides/guide.md): how it works, scenario by scenario, with real log lines

## Layout

- `cmd/ca/`, `internal/pki/`: the Go CA
- `api/`: the Python auth server and resource server, with tests
- `api/proto/`: the gRPC contract. `client/src/main/proto/` holds an identical copy, and a test checks they match
- `client/`: the Java client
- `guides/`: tutorial and guide
- `docs/`: the architecture diagram, served by GitHub Pages

## Contributing, security and license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Released under the [Apache License 2.0](LICENSE).
