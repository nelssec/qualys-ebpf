FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY pkg/ ./pkg/
COPY cmd/ ./cmd/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o qcr ./cmd/main.go

FROM cgr.dev/chainguard/static:latest AS production

COPY --from=builder /app/qcr /qcr

ENTRYPOINT ["/qcr"]

FROM cgr.dev/chainguard/wolfi-base:latest AS eventgen

RUN apk update && apk add --no-cache \
    bash \
    coreutils \
    findutils \
    grep \
    curl \
    wget \
    python3 \
    openssh-client \
    && rm -rf /var/cache/apk/*

COPY --from=builder /app/qcr /usr/local/bin/qcr

WORKDIR /app

USER nonroot
ENTRYPOINT ["/usr/local/bin/qcr"]
CMD ["events", "-i"]
