FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/ ./cmd/...

FROM alpine:3.23
COPY --from=build /out/ /usr/local/bin/
