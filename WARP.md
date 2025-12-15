# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

`whoami` is a lightweight Go webserver that prints OS and HTTP request information. It serves both HTTP and gRPC protocols on the same port, providing endpoints for debugging, testing, and benchmarking network requests.

## Build & Development Commands

### Building
```bash
# Build the binary
make build
# or
CGO_ENABLED=0 go build -a --trimpath --installsuffix cgo --ldflags="-s" -o whoami
```

### Testing
```bash
# Run all tests
make test
# or
go test -v -cover ./...
```

### Linting
```bash
# Run golangci-lint
make check
# or
golangci-lint run
```

### Docker
```bash
# Build Docker image
make image
# which runs: docker build -t traefik/whoami .
```

### Running Locally
```bash
# Basic run
./whoami

# With custom port
./whoami --port 8080

# With TLS
./whoami --cert /path/to/cert.crt --key /path/to/key.key

# With mutual TLS
./whoami --cert /path/to/cert.crt --key /path/to/key.key --cacert /path/to/ca.crt

# With verbose logging
./whoami --verbose

# With custom name
./whoami --name myinstance
```

### Protocol Buffers
```bash
# Regenerate gRPC code from grpc.proto
make protoc
# which runs: protoc --proto_path . ./grpc.proto --go-grpc_out=./ --go_out=./
```

## Architecture

### Single Port, Multiple Protocols
The application uses a unified HTTP multiplexer that serves:
- **HTTP/1.1 and HTTP/2** endpoints (with h2c support for cleartext HTTP/2)
- **gRPC** endpoints on the same port via HTTP/2

This is achieved by registering the gRPC server's handler alongside HTTP handlers in the same `http.ServeMux`.

### HTTP Handlers
All HTTP handlers are defined in `app.go`:
- `/` - `whoamiHandler`: Main endpoint returning request details (supports `?wait=` and `?env=true`)
- `/api` - `apiHandler`: Returns JSON-formatted request data (supports `?env=true`)
- `/bench` - `benchHandler`: Simple benchmark endpoint returning "1"
- `/data` - `dataHandler`: Generates response with specified size (supports `?size=`, `?unit=`, `?attachment=`)
- `/echo` - `echoHandler`: WebSocket echo server
- `/health` - `healthHandler`: Dynamic health check (POST to set status, GET to check)
- `/ready` - `readinessHandler`: Readiness probe for Kubernetes (returns 503 during shutdown)
- `/alive` - `livenessHandler`: Liveness probe for Kubernetes (always returns 200)

### gRPC Service
- Defined in `grpc.proto` under package `whoami`
- Generated code in `grpc/` directory
- Server implementation: `whoamiServer` struct in `app.go`
- Two RPC methods: `Whoami` (returns hostname/IPs) and `Bench` (returns 1)

### Content Generation
The `contentReader` in `content.go` implements `io.Reader` and `io.Seeker` to generate patterned content for the `/data` endpoint without pre-allocating memory. It generates a repeating charset pattern bordered by `|` characters.

### TLS Support
The app supports three TLS modes (controlled by flags):
1. **Plain HTTP** (default): No cert/key
2. **TLS**: With `--cert` and `--key`
3. **Mutual TLS**: With `--cert`, `--key`, and `--cacert`

### Health Check Pattern
The `/health` endpoint uses a shared state (`currentHealthState`) protected by `sync.RWMutex`:
- POST requests update the status code
- GET requests return the current status code
This allows external control of health check responses for testing

### Graceful Shutdown
The application implements graceful shutdown for zero-downtime deployments in Kubernetes:
1. **Signal Handling**: Listens for `SIGTERM` and `SIGINT` signals
2. **Request Tracking**: Tracks in-flight requests using `atomic.Int64` (excludes health check endpoints)
3. **Shutdown Sequence**:
   - Marks service as not ready (readiness probe returns 503)
   - Waits 5 seconds for Kubernetes to update routing tables
   - Waits for all in-flight requests to complete
   - Gracefully shuts down the HTTP server with a 10-second timeout
4. **Kubernetes Probes**:
   - `/ready`: Returns 200 when ready, 503 during shutdown (stops new traffic)
   - `/alive`: Always returns 200 (prevents pod termination during shutdown)

See `k8s-deployment.yaml` for example Kubernetes configuration.

## Code Style

- Uses `golangci-lint` with extensive linters enabled (see `.golangci.yml`)
- Formatters: `gci` and `gofumpt` with extra rules
- Standard lib `errors` package preferred over third-party error libraries
- CGO disabled for static binary compilation
- Tests use parallel execution (`t.Parallel()`)

## Docker Image Registry

When working with Docker images, use Docker Hub (`traefik/whoami`) rather than private registries like `projects.registry.vmware.com`.
