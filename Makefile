VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X ariadns/internal/version.Version=$(VERSION)
.PHONY: build test vet run
build: ; CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ariadns ./cmd/ariadns
test:  ; go test -race ./...
vet:   ; go vet ./...
run:   ; go run ./cmd/ariadns
