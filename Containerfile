FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/ca ./cmd/ca

FROM alpine:3.23
COPY --from=build /out/ca /usr/local/bin/ca
