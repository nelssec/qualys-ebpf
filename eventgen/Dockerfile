FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY cmd/ ./cmd/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o qcr ./cmd/main.go

FROM alpine:3.19

RUN apk add --no-cache \
    bash \
    coreutils \
    findutils \
    grep \
    procps \
    net-tools \
    curl \
    wget \
    python3 \
    openssh-client \
    && rm -rf /var/cache/apk/*

COPY --from=builder /app/qcr /usr/local/bin/qcr

RUN chmod +x /usr/local/bin/qcr

WORKDIR /app

ENTRYPOINT ["/usr/local/bin/qcr"]
CMD ["events", "-i"]
