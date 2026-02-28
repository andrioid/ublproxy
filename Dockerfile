FROM golang:1.25-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /ublproxy .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
RUN addgroup -S ublproxy && adduser -S -G ublproxy ublproxy
COPY --from=build /ublproxy /usr/local/bin/ublproxy

EXPOSE 8080 8443
VOLUME /data
RUN mkdir -p /data && chown ublproxy:ublproxy /data

ENV UBLPROXY_CA_DIR=/data
ENV UBLPROXY_DB=/data/ublproxy.db

USER ublproxy
ENTRYPOINT ["ublproxy"]
