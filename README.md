# service-service-mtls

A runnable demo of service-to-service mTLS with RFC 8705 certificate-bound access tokens. The auth server ties each token to the client certificate that asked for it. A stolen token is useless without the matching private key.

## Run

```sh
podman compose up --build --exit-code-from verify
```

Success: the table shows 5 scenarios matching and the exit code is 0.

Clean up from this directory:

```sh
podman compose down -v
```

## Prerequisites

- podman with `podman compose`

Go is not needed to run the demo. Run unit tests with `go test ./...`.

## Services

| Service | Host name | Role |
|---|---|---|
| `ca` | | Writes the CA, certs and signing key to the `certs` volume |
| `authserver` | `auth.demo` | Issues tokens bound to the client cert |
| `resource` | `api.demo` | Checks the token and the cert match |
| `verify` | | Runs the scenarios and sets the exit code |

Certs and keys live in a named volume and are for this demo only.

## Scenarios

| # | Scenario | Expected |
|---|---|---|
| 1 | `client-a` gets a token and calls the API | 200 |
| 2 | `client-b` replays `client-a`'s token | 401 `thumbprint_mismatch` |
| 3 | Token without `cnf` | 401 `no_cnf` |
| 4 | `client-expired` connects | TLS handshake fails |
| 5 | `client-rogue` connects | TLS handshake fails |

## More

- [docs/runtime-architecture.html](docs/runtime-architecture.html): interactive runtime architecture diagram
- [docs/guide.md](docs/guide.md): how it works, scenario by scenario
