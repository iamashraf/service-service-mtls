# Contributing

Issues and pull requests are welcome. Keep changes small and tied to one purpose.

## Run the tests

```sh
go vet ./... && go test ./...
cd api && python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt && .venv/bin/pytest -q
```

Run the full demo before you open a pull request. It must exit 0.

```sh
podman compose up --build --exit-code-from client
podman compose down -v
```

## Conventions

- Add a test with any change to a check or a status code.
- Write docs in plain words, with short sentences and no em dashes.
- Commit messages follow `type(scope): summary`, for example `fix(api): reject empty issuer`.
- Do not commit keys or certs. `certs/` and `*.key` are ignored.
