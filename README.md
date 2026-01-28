# ollama-proxy

Minimal reverse proxy that forwards requests from http://localhost:11434 to https://ollama.com while preserving path, headers and payload.

## Build

Requires Go 1.21+

```sh
go build ./cmd/ollama-proxy
```

## Run

Defaults:
- listen: `127.0.0.1:11434` (bind to localhost for safety)
- target: `https://ollama.com`

Run with flags:
```sh
./ollama-proxy -listen :11434 -target https://ollama.com
```

Or using environment variables (shell):
```sh
LISTEN=:11434 TARGET=https://ollama.com ./ollama-proxy
```

## Authentication (Ollama API key)

Ollama cloud requires a Bearer token set in the `Authorization` header. Provide the key with the `-api-key` flag or `OLLAMA_API_KEY` environment variable. By default the proxy will inject/override the `Authorization` header for every request to emulate a local Ollama install. Use `-preserve-auth` to preserve client-supplied `Authorization` headers instead of overriding. The proxy will not log the Authorization header or the key.

Example:

```sh
export OLLAMA_API_KEY="sk-..."
./ollama-proxy -listen :11434 -target https://ollama.com
curl -v http://localhost:11434/v1/models
```

## Test

```sh
curl -v http://localhost:11434/api/tags
```

## Docker

Build and run with docker:

```sh
# build image
docker build -t ollama-proxy:latest .
# run (pass OLLAMA_API_KEY via env)
# bind port to localhost on the host to avoid exposing the service publicly
# the container listens on all interfaces (0.0.0.0) by default; this image sets the default listen address to :11434
# override the listen address inside the container by passing flags after the image:
#   docker run --rm -p 127.0.0.1:11434:11434 -e OLLAMA_API_KEY="$OLLAMA_API_KEY" ollama-proxy:latest -listen 127.0.0.1:11434
# or when using docker-compose set the service `command` (see `docker-compose.yml`):
#   command: ["-listen", "127.0.0.1:11434"]

docker run --rm -p 127.0.0.1:11434:11434 -e OLLAMA_API_KEY="$OLLAMA_API_KEY" ollama-proxy:latest
```

## Docker Compose

Quickly run the proxy with Docker Compose. Copy `.env.example` to `.env` and set `OLLAMA_API_KEY` (do not commit `.env` to version control):

```sh
cp .env.example .env
# Edit .env and set OLLAMA_API_KEY
docker-compose up -d --build
```

The compose file maps port `11434` on localhost to the container. The `.env` file is read by Compose and is a convenient way to pass `OLLAMA_API_KEY` without exposing it in the `docker-compose.yml` file.
