FROM docker.io/library/golang:1.26 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ca ./cmd/ca

FROM docker.io/library/alpine:3.23
COPY --from=build /out/ca /usr/local/bin/ca
# 65534 is nobody: the CA needs no privileges and listens above port 1024
USER 65534:65534
EXPOSE 8080
CMD ["ca"]
