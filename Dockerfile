# Build stage
FROM golang:1.21-alpine AS builder
RUN apk add --no-cache ca-certificates git
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/ollama-proxy ./cmd/ollama-proxy

# Runtime stage
FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=builder /bin/ollama-proxy /usr/local/bin/ollama-proxy
USER 1000:1000
EXPOSE 11434
ENTRYPOINT ["/usr/local/bin/ollama-proxy"]
