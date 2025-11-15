#!/bin/bash

set -e

echo "================================================"
echo "  Zygarde Build Script"
echo "  Guardian of the Kernel"
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

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${RED}[-] Error: Please do not run this script as root or with sudo${NC}"
    echo "  The script will ask for sudo privileges only when needed (for bpftool)"
    exit 1
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
    echo -e "${GREEN}[+] Go: $GO_VERSION${NC}"
else
    echo -e "${RED}[-] Go: Not found${NC}"
    echo "  Install: https://golang.org/doc/install"
    ALL_OK=false
fi

# Check Clang
if command_exists clang; then
    CLANG_VERSION=$(clang --version | head -1)
    echo -e "${GREEN}[+] Clang: $CLANG_VERSION${NC}"
else
    echo -e "${RED}[-] Clang: Not found${NC}"
    ALL_OK=false
fi

# Check kernel version
KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

if [ "$KERNEL_MAJOR" -gt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 8 ]); then
    echo -e "${GREEN}[+] Kernel: $KERNEL_VERSION (>= 5.8)${NC}"
else
    echo -e "${YELLOW}[*] Kernel: $KERNEL_VERSION (< 5.8, may not work)${NC}"
fi

# Check BTF
if [ -f /sys/kernel/btf/vmlinux ]; then
    BTF_SIZE=$(stat -f %z /sys/kernel/btf/vmlinux 2>/dev/null || stat -c %s /sys/kernel/btf/vmlinux 2>/dev/null)
    if [ -n "$BTF_SIZE" ] && [ "$BTF_SIZE" -gt 0 ] 2>/dev/null; then
        echo -e "${GREEN}[+] BTF: Available ($BTF_SIZE bytes)${NC}"
    else
        echo -e "${GREEN}[+] BTF: Available${NC}"
    fi
else
    echo -e "${RED}[-] BTF: Not available${NC}"
    echo "  Your kernel needs CONFIG_DEBUG_INFO_BTF=y"
    ALL_OK=false
fi

echo ""

if [ "$ALL_OK" = false ]; then
    echo -e "${RED}[-] Prerequisites not met. Please install missing components.${NC}"
    echo -e "  ${YELLOW}sudo apt update${NC}"
    echo -e "  ${YELLOW}sudo apt install -y golang clang llvm libbpf-dev linux-headers-\$(uname -r) bpftool${NC}"
    exit 1
fi

echo -e "${GREEN}[+] All prerequisites met${NC}"
echo ""

# Show help message for potential build issues
echo "If something goes wrong during the build, ensure you have all packages:"
echo -e "  ${YELLOW}sudo apt update${NC}"
echo -e "  ${YELLOW}sudo apt install -y golang clang llvm libbpf-dev linux-headers-\$(uname -r) bpftool${NC}"
echo ""

# Step 1: Generate vmlinux.h
echo "================================================"
echo "Step 1: Generating vmlinux.h"
echo "================================================"
echo ""

if [ ! -f bpf/vmlinux.h ] || [ "$1" = "--force" ]; then
    if [ "$1" = "--force" ]; then
        echo -e "${YELLOW}[*] Forcing regeneration of vmlinux.h${NC}"
    else
        echo -e "${YELLOW}[*] vmlinux.h not found${NC}"
    fi
    echo ""
    
    # Ask user if they want to generate vmlinux.h
    echo "vmlinux.h is required for building the eBPF program."
    echo "This can be generated from your kernel's BTF information using bpftool."
    echo ""
    read -p "Generate vmlinux.h now? This requires sudo access. [y/N]: " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo -e "${YELLOW}[*] Build cancelled${NC}"
        echo "Please provide a pre-generated bpf/vmlinux.h file and run the script again."
        echo ""
        echo "To generate it manually, run:"
        echo "  sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h"
        echo ""
        exit 0
    fi
    
    echo ""
    echo "Checking for bpftool with sudo..."
    
    # Check if bpftool exists with sudo
    if ! sudo which bpftool >/dev/null 2>&1 && ! sudo command -v bpftool >/dev/null 2>&1; then
        echo -e "${RED}[-] bpftool not found${NC}"
        echo ""
        echo "Please install bpftool:"
        echo "  Ubuntu/Debian: sudo apt install bpftool"
        echo "  Fedora/RHEL:   sudo dnf install bpftool"
        echo ""
        echo "Alternatively, provide a pre-generated bpf/vmlinux.h file."
        exit 1
    fi
    
    echo "Generating vmlinux.h from kernel BTF..."
    
    # Generate vmlinux.h with sudo
    if sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h 2>/dev/null; then
        echo -e "${GREEN}[+] Generated bpf/vmlinux.h${NC}"
        # Fix ownership
        sudo chown $USER:$(id -gn) bpf/vmlinux.h 2>/dev/null || true
    else
        echo -e "${RED}[-] Failed to generate vmlinux.h${NC}"
        echo ""
        echo "Try running manually:"
        echo "  sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h"
        echo ""
        exit 1
    fi
else
    echo -e "${GREEN}[+] bpf/vmlinux.h already exists (use --force to regenerate)${NC}"
fi

echo ""

# Step 2: Install Go dependencies
echo "================================================"
echo "Step 2: Installing Go dependencies"
echo "================================================"
echo ""

echo "Running go mod tidy..."
go mod tidy
echo -e "${GREEN}[+] Dependencies installed${NC}"

echo ""

# Step 3: Install bpf2go
echo "================================================"
echo "Step 3: Installing bpf2go"
echo "================================================"
echo ""

echo "Installing bpf2go tool..."
go install github.com/cilium/ebpf/cmd/bpf2go@latest
echo -e "${GREEN}[+] bpf2go installed${NC}"

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
echo -e "${GREEN}[+] eBPF bindings generated${NC}"

echo ""

# Step 5: Build the binary
echo "================================================"
echo "Step 5: Building zygarde binary"
echo "================================================"
echo ""

echo "Compiling static binary..."
CGO_ENABLED=0 go build -ldflags="-s -w" -o zygarde .

if [ -f zygarde ]; then
    BINARY_SIZE=$(stat -f %z zygarde 2>/dev/null || stat -c %s zygarde 2>/dev/null)
    if [ -n "$BINARY_SIZE" ] && [ "$BINARY_SIZE" -gt 0 ] 2>/dev/null; then
        BINARY_SIZE_MB=$(awk "BEGIN {printf \"%.2f\", $BINARY_SIZE / 1048576}")
        echo -e "${GREEN}[+] Built zygarde binary (${BINARY_SIZE_MB}MB)${NC}"
    else
        echo -e "${GREEN}[+] Built zygarde binary${NC}"
    fi
    echo ""
    ls -lh zygarde
else
    echo -e "${RED}[-] Build failed${NC}"
    exit 1
fi

echo ""
echo "================================================"
echo "  Build Complete!"
echo "================================================"
echo ""
echo "To run the tool:"
echo "  sudo ./zygarde"
echo ""
echo "To install system-wide:"
echo "  sudo make install"
echo ""
echo -e "${GREEN}[+] The binary is statically compiled and portable${NC}"
echo "    It can run on any Linux system with:"
echo "    - Kernel >= 5.8"
echo "    - BTF support (CONFIG_DEBUG_INFO_BTF=y)"
echo ""
