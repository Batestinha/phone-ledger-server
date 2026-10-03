# syntax=docker/dockerfile:1
FROM golang:1.26.8-alpine3.24 AS build
ENV GOMAXPROCS=2
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -p=2 -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/phone-ledger-server ./cmd/phone-ledger-server

FROM alpine:3.24
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 phoneledger \
    && adduser -S -D -H -u 10001 -G phoneledger phoneledger \
    && install -d -o phoneledger -g phoneledger -m 0700 /data
COPY --from=build /out/phone-ledger-server /usr/local/bin/phone-ledger-server
USER phoneledger:phoneledger
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["phone-ledger-server"]
CMD ["serve", "--listen", "0.0.0.0:8080", "--db", "/data/phone-ledger.db"]
