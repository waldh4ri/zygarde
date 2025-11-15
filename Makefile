.PHONY: help generate build clean test install vmlinux

# Default target
all: build

# Help target
help:
	@echo "Zygarde - eBPF Rootkit Detection Tool"
	@echo "Guardian of the Kernel"
	@echo ""
	@echo "Available targets:"
	@echo "  make generate    - Generate vmlinux.h and eBPF Go bindings"
	@echo "  make build       - Build the zygarde binary"
	@echo "  make clean       - Remove generated files and binaries"
	@echo "  make test        - Run tests"
	@echo "  make install     - Install zygarde to /usr/local/bin"
	@echo "  make vmlinux     - Generate vmlinux.h from running kernel"
	@echo "  make fmt         - Format Go code"
	@echo "  make vet         - Run go vet"
	@echo ""

# Generate vmlinux.h from the running kernel
vmlinux:
	@echo "Generating vmlinux.h from running kernel..."
	@if ! command -v bpftool >/dev/null 2>&1; then \
		echo "Error: bpftool not found. Please install it:"; \
		echo "  Ubuntu/Debian: sudo apt-get install linux-tools-common linux-tools-$$(uname -r)"; \
		echo "  Fedora/RHEL:   sudo dnf install bpftool"; \
		echo "  Arch:          sudo pacman -S bpf"; \
		exit 1; \
	fi
	@sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
	@echo "✓ Generated bpf/vmlinux.h"

# Generate eBPF Go bindings
generate: vmlinux
	@echo "Generating eBPF Go bindings..."
	@if ! command -v clang >/dev/null 2>&1; then \
		echo "Error: clang not found. Please install it."; \
		exit 1; \
	fi
	cd checks && go generate
	@echo "✓ Generated eBPF bindings"

# Build the binary
build: generate
	@echo "Building zygarde..."
	CGO_ENABLED=0 go build -ldflags="-s -w" -o zygarde .
	@echo "✓ Built zygarde binary"
	@ls -lh zygarde

# Clean generated files and binaries
clean:
	@echo "Cleaning..."
	rm -f zygarde
	rm -f checks/bpf_bpfel.go checks/bpf_bpfeb.go
	rm -f checks/bpf_bpfel.o checks/bpf_bpfeb.o
	@echo "✓ Cleaned"

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Format Go code
fmt:
	@echo "Formatting code..."
	go fmt ./...
	@echo "✓ Code formatted"

# Run go vet
vet:
	@echo "Running go vet..."
	go vet ./...
	@echo "✓ Vet passed"

# Install to system
install: build
	@echo "Installing zygarde to /usr/local/bin..."
	sudo install -m 755 zygarde /usr/local/bin/zygarde
	@echo "✓ Installed zygarde"

# Check prerequisites
check-prereqs:
	@echo "Checking prerequisites..."
	@echo -n "Go:      "; which go && go version || echo "✗ Not found"
	@echo -n "Clang:   "; which clang && clang --version | head -1 || echo "✗ Not found"
	@echo -n "bpftool: "; which bpftool && bpftool version || echo "✗ Not found"
	@echo -n "Kernel:  "; uname -r
	@echo -n "BTF:     "; test -f /sys/kernel/btf/vmlinux && echo "✓ Available" || echo "✗ Not available"
	@echo ""
