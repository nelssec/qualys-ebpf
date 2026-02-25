FROM golang:1.24-alpine AS builder

ENV GOTOOLCHAIN=auto

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY pkg/ ./pkg/
COPY cmd/ ./cmd/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o qcr ./cmd/main.go

FROM gcr.io/distroless/static-debian12:nonroot AS production

COPY --from=builder /app/qcr /qcr

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/qcr", "version"]

ENTRYPOINT ["/qcr"]

FROM alpine:3.20 AS eventgen

RUN apk upgrade --no-cache && \
    apk add --no-cache \
    bash \
    coreutils \
    findutils \
    grep \
    curl \
    wget \
    python3 \
    openssh-client \
    && rm -rf /var/cache/apk/*

RUN adduser -D -u 10001 qcr

COPY --from=builder /app/qcr /usr/local/bin/qcr

WORKDIR /app
USER qcr

ENTRYPOINT ["/usr/local/bin/qcr"]
CMD ["events", "-i"]
