#!/bin/bash

set -e

echo "================================================"
echo "  GoHunt Build Script"
echo "================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${RED}[-] Error: This tool only works on Linux${NC}"
    exit 1
fi

# Check for root (needed for bpftool)
if [[ $EUID -eq 0 ]]; then
   echo -e "${YELLOW}[*] Warning: Running as root${NC}"
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
echo "Checking prerequisites..."
echo ""

ALL_OK=true

# Check Go
if command_exists go; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo -e "${GREEN}[+]${NC} Go: $GO_VERSION"
else
    echo -e "${RED}[-]${NC} Go: Not found"
    echo "  Install: https://golang.org/doc/install"
    ALL_OK=false
fi

# Check Clang
if command_exists clang; then
    CLANG_VERSION=$(clang --version | head -1)
    echo -e "${GREEN}[+]${NC} Clang: $CLANG_VERSION"
else
    echo -e "${RED}[-]${NC} Clang: Not found"
    echo "  Ubuntu/Debian: sudo apt-get install clang"
    echo "  Fedora/RHEL:   sudo dnf install clang"
    ALL_OK=false
fi

# Check bpftool (optional if vmlinux.h exists)
if command_exists bpftool; then
    BPFTOOL_VERSION=$(bpftool version 2>&1 | head -1)
    echo -e "${GREEN}[+]${NC} bpftool: $BPFTOOL_VERSION"
elif [ -f bpf/vmlinux.h ]; then
    echo -e "${YELLOW}[*]${NC} bpftool: Not found (but vmlinux.h exists)"
else
    echo -e "${RED}[-]${NC} bpftool: Not found (needed to generate vmlinux.h)"
    echo "  Ubuntu/Debian: sudo apt-get install linux-tools-common linux-tools-\$(uname -r)"
    echo "  Fedora/RHEL:   sudo dnf install bpftool"
    ALL_OK=false
fi

# Check kernel version
KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

if [ "$KERNEL_MAJOR" -gt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 8 ]); then
    echo -e "${GREEN}[+]${NC} Kernel: $KERNEL_VERSION (>= 5.8)"
else
    echo -e "${YELLOW}[*]${NC} Kernel: $KERNEL_VERSION (< 5.8, may not work)"
fi

# Check BTF
if [ -f /sys/kernel/btf/vmlinux ]; then
    BTF_SIZE=$(stat -f %z /sys/kernel/btf/vmlinux 2>/dev/null || stat -c %s /sys/kernel/btf/vmlinux 2>/dev/null)
    if [ -n "$BTF_SIZE" ] && [ "$BTF_SIZE" -gt 0 ] 2>/dev/null; then
        echo -e "${GREEN}[+]${NC} BTF: Available ($BTF_SIZE bytes)"
    else
        echo -e "${GREEN}[+]${NC} BTF: Available"
    fi
else
    echo -e "${RED}[-]${NC} BTF: Not available"
    echo "  Your kernel needs CONFIG_DEBUG_INFO_BTF=y"
    ALL_OK=false
fi

echo ""

if [ "$ALL_OK" = false ]; then
    echo -e "${RED}[-] Prerequisites not met. Please install missing components.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] All prerequisites met${NC}"
echo ""

# Step 1: Generate vmlinux.h
echo "================================================"
echo "Step 1: Generating vmlinux.h"
echo "================================================"
echo ""

if [ ! -f bpf/vmlinux.h ] || [ "$1" = "--force" ]; then
    if ! command_exists bpftool; then
        echo -e "${RED}[-]${NC} bpftool not found, cannot generate vmlinux.h"
        echo "  Please install bpftool or provide a pre-generated vmlinux.h"
        echo "  Ubuntu/Debian: sudo apt-get install linux-tools-common linux-tools-\$(uname -r)"
        exit 1
    fi
    
    echo "Generating vmlinux.h from kernel BTF..."
    
    # Try to run bpftool - use sudo if needed, but redirect as user
    if sudo -n bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h 2>/dev/null; then
        echo -e "${GREEN}[+]${NC} Generated bpf/vmlinux.h"
    elif sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | tee bpf/vmlinux.h > /dev/null; then
        # Fix ownership if created by sudo
        if [ -f bpf/vmlinux.h ] && [ "$(stat -c %U bpf/vmlinux.h 2>/dev/null)" = "root" ]; then
            sudo chown $USER:$(id -gn) bpf/vmlinux.h
        fi
        echo -e "${GREEN}[+]${NC} Generated bpf/vmlinux.h"
    else
        echo -e "${RED}[-]${NC} Failed to generate vmlinux.h"
        echo "  Try running manually: sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h"
        exit 1
    fi
else
    echo -e "${GREEN}[+]${NC} bpf/vmlinux.h already exists (use --force to regenerate)"
fi

echo ""

# Step 2: Install Go dependencies
echo "================================================"
echo "Step 2: Installing Go dependencies"
echo "================================================"
echo ""

echo "Running go mod tidy..."
go mod tidy
echo -e "${GREEN}[+]${NC} Dependencies installed"

echo ""

# Step 3: Install bpf2go
echo "================================================"
echo "Step 3: Installing bpf2go"
echo "================================================"
echo ""

echo "Installing bpf2go tool..."
go install github.com/cilium/ebpf/cmd/bpf2go@latest
echo -e "${GREEN}[+]${NC} bpf2go installed"

echo ""

# Step 4: Generate eBPF bindings
echo "================================================"
echo "Step 4: Generating eBPF bindings"
echo "================================================"
echo ""

cd checks
echo "Running go generate..."
go generate
cd ..
echo -e "${GREEN}[+]${NC} eBPF bindings generated"

echo ""

# Step 5: Build the binary
echo "================================================"
echo "Step 5: Building gohunt binary"
echo "================================================"
echo ""

echo "Compiling static binary..."
CGO_ENABLED=0 go build -ldflags="-s -w" -o gohunt .

if [ -f gohunt ]; then
    BINARY_SIZE=$(stat -f %z gohunt 2>/dev/null || stat -c %s gohunt 2>/dev/null)
    if [ -n "$BINARY_SIZE" ] && [ "$BINARY_SIZE" -gt 0 ] 2>/dev/null; then
        BINARY_SIZE_MB=$(awk "BEGIN {printf \"%.2f\", $BINARY_SIZE / 1048576}")
        echo -e "${GREEN}[+]${NC} Built gohunt binary (${BINARY_SIZE_MB}MB)"
    else
        echo -e "${GREEN}[+]${NC} Built gohunt binary"
    fi
    echo ""
    ls -lh gohunt
else
    echo -e "${RED}[-]${NC} Build failed"
    exit 1
fi

echo ""
echo "================================================"
echo "  Build Complete!"
echo "================================================"
echo ""
echo "To run the tool:"
echo "  sudo ./gohunt"
echo ""
echo "To install system-wide:"
echo "  sudo make install"
echo ""
