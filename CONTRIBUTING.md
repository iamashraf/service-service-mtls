# Contributing

Issues and pull requests are welcome. Keep changes small and tied to one purpose.

## Run the tests

```sh
go vet ./... && go test ./...
cd api && python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt && .venv/bin/pytest -q
```

Run the full demo before you open a pull request. It must exit 0. It needs `.env.local`; see the [README](README.md#see-it-in-2-minutes).

```sh
podman compose --env-file .env.local up --build --exit-code-from client
podman compose --env-file .env.local down -v
```

## Check the containers and CI

```sh
podman compose --env-file .env.local up -d ca api
podman exec mtlsdemo-api-1 id      # expect uid=65534(nobody)
podman compose --env-file .env.local down -v
gh run watch                       # follow the latest CI run
```

## Publish the diagram

The README links to the architecture diagram on GitHub Pages. After the repo is public, open Settings, then Pages. Set the source to branch `main` and folder `/docs`. The diagram then loads at `https://iamashraf.github.io/service-service-mtls/runtime-architecture.html`. GitHub does not serve Pages from a private repo on the free plan.

## Conventions

- Add a test with any change to a check or a status code.
- Write docs in plain words, with short sentences and no em dashes.
- Commit messages follow `type(scope): summary`, for example `fix(api): reject empty issuer`.
- Do not commit keys or certs. `certs/` and `*.key` are ignored.
