# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download || true

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /policy-operator ./cmd/main.go

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates

COPY --from=builder /policy-operator /usr/local/bin/policy-operator

# Run as non-root
RUN adduser -D -u 1000 operator
USER operator

ENTRYPOINT ["/usr/local/bin/policy-operator"]
