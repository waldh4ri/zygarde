# Toolchain image for building and testing Zygarde (Go, clang, llvm).
# Used by `make docker-*`; works the same from Linux, macOS, WSL or Windows.
FROM golang:1.25-trixie
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang llvm \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
