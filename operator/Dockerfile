# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .

# Build both binaries
RUN CGO_ENABLED=0 GOOS=linux go build -o /policy-operator ./cmd/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o /webhook ./cmd/webhook/main.go

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates kubectl

COPY --from=builder /policy-operator /usr/local/bin/policy-operator
COPY --from=builder /webhook /usr/local/bin/webhook

RUN adduser -D -u 1000 operator
USER operator

ENTRYPOINT ["/usr/local/bin/policy-operator"]
