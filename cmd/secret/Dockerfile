FROM alpine:latest AS builder
RUN apk add --no-cache tzdata

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY secret_amd64 /secret
ENTRYPOINT ["/secret", "server"]
