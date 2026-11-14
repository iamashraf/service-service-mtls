# service-service-mtls

**Demo only. Not for production.** A runnable demo of how two services prove who they are (AuthN) and what they may do (AuthZ). Calls use mutual TLS, and each access token is bound to the client's certificate. A stolen token is useless on any other cert.

One command starts a Go certificate authority, a FastAPI server and a Java 25 client. The client runs seven checks and exits 0 only if every one behaves as expected.

## What this demonstrates

| Skill | Where to see it |
|---|---|
| PKI and mutual TLS | [Go CA](cmd/ca/handler.go), [TLS 1.3 server setup](api/app/tls.py) |
| Certificate-bound tokens ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)) | [token and thumbprint code](api/app/tokens.py) |
| Authorization design | [policy table](api/app/policy.py), [ordered checks](api/app/guard.py) |
| Three languages in one system | Go, Python 3.14, Java 25 |
| Containers | [compose.yaml](compose.yaml), three Containerfiles, podman |
| Testing | Go tests, 49 pytest tests including live TLS, an end-to-end run |

## See it in 2 minutes

You need `podman` with `podman compose`.

```sh
podman compose up --build --exit-code-from client
```

Real output from a run:

```text
SCENARIO                         EXPECTED                   MATCH  ACTUAL
1 writer GET /orders             200                        yes    200
1 writer POST /orders            201                        yes    201
2 reader POST /orders            403 insufficient_scope     yes    403 insufficient_scope
2 reader GET /orders             200                        yes    200
3 reader replays writer token    401 thumbprint_mismatch    yes    401 thumbprint_mismatch
4 rogue cert                     TLS handshake rejected     yes    java.io.IOException: Connection reset
4 control: writer still served   200                        yes    200
```

Clean up with `podman compose down -v`.

## Architecture

The [interactive runtime architecture diagram](https://iamashraf.github.io/service-service-mtls/runtime-architecture.html) shows the services, the trust boundary and the request path.

| Service | Stack | Address | Job |
|---|---|---|---|
| ca | Go | `ca.demo:8080` | Issues certs at `POST /enroll` |
| api | FastAPI on Hypercorn | `api.demo:8443` | Requires a client cert, issues and checks tokens |
| client | Java 25 | none | Runs the scenarios and sets the exit code |

1. Each service enrolls with the CA and gets a cert.
2. The client calls `POST /token` over mTLS.
3. The API signs a token that carries the SHA-256 thumbprint of the client cert.
4. The client calls `/orders` with the token.
5. The API checks the token, the thumbprint and the scope.

## Design decisions

- **Bind the token to the cert.** The token holds the cert thumbprint, so a copy sent over another connection fails with 401.
- **Scopes come from a server policy.** The API looks up the cert CN. Nothing in the request can raise a scope.
- **401 and 403 mean different things.** 401 means identity or binding failed. 403 means the identity is known and the action is not allowed.
- **TLS 1.3 only.** Hypercorn allows 1.2 by default, so a `Config` subclass raises the floor. A test shows the server rejects a 1.2 client.
- **Constant-time compare.** The thumbprint check does not leak timing.
- **A pinned adapter for the peer cert.** ASGI servers verify client certs but do not pass them to the app. A small `TCPServer` subclass does, and a test checks that concurrent connections never see each other's cert.

## Container security

All three services run with the same limits. The [guide](docs/guide.md#container-hardening) gives the reason for each.

- They run as `nobody` (uid 65534), not root.
- The root filesystem is read-only. Only tmpfs mounts are writable: `/tmp`, `/var/tmp` and `/dev/shm`.
- All Linux capabilities are dropped, and `no-new-privileges` is set.
- `client` starts after the `api` healthcheck passes, and `api` after the `ca` healthcheck.
- Each build context is an allowlist, and `.env` files are excluded everywhere, so a stray secret file does not reach an image.

## Tests

- `go test ./...` covers the CA and cert issuing.
- `pytest` in `api/` runs 49 tests. They include real TLS handshakes, every rejection reason, and `alg: none` and HS256 tokens.
- The client run is the end-to-end test. Breaking the thumbprint check makes it exit 1.
- [CI](.github/workflows/ci.yml) runs the Go and Python tests on every push.

## Known limits

- `/enroll` is unauthenticated plain HTTP and returns the private key. A real CA takes a CSR and checks who asks.
- The apps trust the CA cert from that same call.
- There is no rotation, revocation or key publishing (JWKS).
- A TLS-terminating proxy in front of the API would hide the client cert and break the binding.
- The Java client has no unit tests. The end-to-end run covers it.

## Docs

- [docs/tutorial.md](docs/tutorial.md): step-by-step tutorial with links to the code and the standards
- [docs/guide.md](docs/guide.md): how it works, scenario by scenario, with real log lines

## Layout

- `cmd/ca/`, `internal/pki/`: the Go CA
- `api/`: the FastAPI server and its tests
- `client/`: the Java client
- `docs/`: tutorial, guide and the architecture diagram

## Contributing, security and license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Released under the [Apache License 2.0](LICENSE).
