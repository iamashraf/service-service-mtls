# service-service-mtls

A runnable demo of AuthN and AuthZ with certificate-bound access tokens. A Go mock CA hands out certs. A FastAPI server verifies the client cert, then issues and checks a token bound to it. A Java 25 client calls the server, and a stolen token is useless on another cert.

## Run

```sh
podman compose up --build --exit-code-from client
```

Success: the client prints a result table where every row says `yes` in the MATCH column, and the exit code is 0.

```sh
podman compose down -v
```

## Prerequisites

- podman with `podman compose`. Nothing else is needed to run.
- Optional: `go test ./...` for the CA tests and `pytest` in `api/`.

## Services

| Service | Stack | Address | Endpoints |
|---|---|---|---|
| ca | Go mock CA | `ca.demo:8080` | `POST /enroll` |
| api | FastAPI on Hypercorn | `api.demo:8443` | `POST /token`, `GET /orders`, `POST /orders` |
| client | Java 25 | none | Runs the scenarios and sets the exit code |

## Scenarios

| Scenario | Result |
|---|---|
| writer `GET /orders` | 200 |
| writer `POST /orders` | 201 |
| reader `POST /orders` | 403 `insufficient_scope` |
| reader `GET /orders` | 200 |
| reader replays the writer's token | 401 `thumbprint_mismatch` |
| rogue-CA cert | TLS handshake rejected |
| control: writer still served | 200 |

## Demo shortcuts

- `/enroll` is unauthenticated plain HTTP and returns the private key. A real CA takes a CSR and checks who asks.
- The apps trust the CA cert from that same call.
- There is no rotation or revocation.

## More

- [docs/guide.md](docs/guide.md): how it works, scenario by scenario
- [docs/runtime-architecture.html](docs/runtime-architecture.html): interactive runtime diagram
