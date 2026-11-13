# Zygarde - eBPF rootkit detection
#
# Native targets need Go and clang on Linux. The docker-* targets run the same
# steps in a toolchain container, from any OS with Docker.

GO       ?= go
ARCHES   := amd64 arm64
# Pinned dev tools, run with `go run` so they stay out of go.mod. They need a
# newer Go than go.mod asks for, hence GOTOOLCHAIN=auto.
GOLANGCI := GOTOOLCHAIN=auto $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
# The one place the vimto version is set: CI installs it with `make install-vimto`
# and the VM test image gets it as a build argument.
VIMTO_VERSION := v0.4.0
GOVULN   := GOTOOLCHAIN=auto $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.9.0

# Stamp binaries with the git revision when it is known (empty otherwise, in
# which case the default in cmd/zygarde/main.go applies).
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null)
LDFLAGS  := -s -w $(if $(VERSION),-X main.version=$(VERSION))
IMAGE    := zygarde-build
DOCKER   := docker run --rm -e VERSION="$(VERSION)" -v "$(CURDIR):/src" -v zygarde-gomod:/go/pkg/mod -w /src $(IMAGE)

.PHONY: all help generate build dist test vet fmt clean \
        check fmt-check tidy-check vet-all test-race lint vuln \
        docker-check docker-image docker-generate docker-build docker-dist docker-test docker-run

all: build

help:
	@echo "make generate        compile BPF programs and Go bindings (needs clang)"
	@echo "make build           build ./zygarde for the host architecture"
	@echo "make dist            build static binaries for $(ARCHES) into dist/"
	@echo "make test            run unit tests"
	@echo "make vet             run go vet"
	@echo "make check           run every static check and the race tests (see below)"
	@echo "make docker-check    the same, inside the toolchain image"
	@echo "make docker-<target> run generate/build/test inside the toolchain image"
	@echo "make docker-run      run ./zygarde in a privileged container (local smoke test)"

# clang numbers some BTF forward declarations differently depending on the
# build host CPU; bpfsame keeps the committed object when nothing else changed.
generate:
	$(GO) generate ./... && $(GO) run ./test/bpfsame

build:
	CGO_ENABLED=0 GOOS=linux $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o zygarde ./cmd/zygarde

dist:
	@mkdir -p dist
	@for arch in $(ARCHES); do \
		echo "building dist/zygarde-linux-$$arch"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags="$(LDFLAGS)" \
			-o dist/zygarde-linux-$$arch ./cmd/zygarde || exit 1; \
	done

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

# --- Static checks -----------------------------------------------------------
# check = fmt-check tidy-check vet-all lint vuln test-race. CI runs the same
# targets, so a green `make docker-check` means a green pipeline.
check: fmt-check tidy-check vet-all lint vuln test-race

fmt-check:
	@out=$$(gofmt -l $$($(GO) list -f '{{.Dir}}' ./...)); \
	if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

tidy-check:
	$(GO) mod tidy -diff
	$(GO) mod verify

# Vet every architecture we ship (the code base is Linux-only).
vet-all:
	GOOS=linux GOARCH=amd64 $(GO) vet ./...
	GOOS=linux GOARCH=arm64 $(GO) vet ./...

lint:
	$(GOLANGCI) run ./...

vuln:
	$(GOVULN) ./...

# -race needs cgo; -shuffle and -count=1 flush out order dependence and caching.
test-race:
	CGO_ENABLED=1 $(GO) test -race -shuffle=on -count=1 -timeout=5m ./...

clean:
	rm -rf zygarde dist

docker-image:
	docker build -q -t $(IMAGE) build/

docker-generate: docker-image
	$(DOCKER) sh -c '$(GO) generate ./... && $(GO) run ./test/bpfsame'

docker-dist: docker-image
	$(DOCKER) make dist

docker-build: docker-image
	$(DOCKER) make build

docker-check: docker-image
	$(DOCKER) make check

docker-test: docker-image
	$(DOCKER) sh -c '$(GO) vet ./... && $(GO) test ./...'

# The container shares the Docker host's kernel (on Docker Desktop, its VM).
docker-run: docker-build
	docker run --rm --privileged --pid=host -v "$(CURDIR):/src" -w /src debian:13 ./zygarde $(ARGS)

# --- Kernel matrix (QEMU/KVM inside a privileged container) -----------------
# vm-upstream: upstream LTS kernels from ghcr.io/cilium/ci-kernels, via vimto.
# vm-distro:   official distribution cloud images (test/vm/distros.txt).
# Pass KERNELS="6.1.188 ..." or DISTROS="debian-12 ..." to run a subset.
VMTEST := docker run --rm --privileged -v "$(CURDIR):/src" -v zygarde-gomod:/go/pkg/mod \
          -v zygarde-vmimages:/images -e JOBS -w /src zygarde-vmtest

.PHONY: vm-image install-vimto vm-upstream vm-distro vm-report

vm-image:
	docker build -q -t zygarde-vmtest --build-arg VIMTO_VERSION=$(VIMTO_VERSION) -f build/vmtest.Dockerfile build/

install-vimto:
	CGO_ENABLED=0 $(GO) install lmb.io/vimto@$(VIMTO_VERSION)

vm-upstream: docker-build vm-image
	$(VMTEST) bash test/vm/upstream.sh $(KERNELS)
	$(VMTEST) go run ./test/vm/report test/vm/out

vm-distro: docker-dist vm-image
	$(VMTEST) bash test/vm/distro.sh $(DISTROS)
	$(VMTEST) go run ./test/vm/report test/vm/out

vm-report:
	$(VMTEST) go run ./test/vm/report test/vm/out
