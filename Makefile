# Zygarde - eBPF rootkit detection
#
# Native targets need Go and clang on Linux. The docker-* targets run the same
# steps in a toolchain container, from any OS with Docker.

GO       ?= go
ARCHES   := amd64 arm64
LDFLAGS  := -s -w
IMAGE    := zygarde-build
DOCKER   := docker run --rm -v "$(CURDIR):/src" -v zygarde-gomod:/go/pkg/mod -w /src $(IMAGE)

.PHONY: all help generate build dist test vet fmt clean \
        docker-image docker-generate docker-build docker-dist docker-test docker-run

all: build

help:
	@echo "make generate        compile BPF programs and Go bindings (needs clang)"
	@echo "make build           build ./zygarde for the host architecture"
	@echo "make dist            build static binaries for $(ARCHES) into dist/"
	@echo "make test            run unit tests"
	@echo "make vet             run go vet"
	@echo "make docker-<target> run generate/build/test inside the toolchain image"
	@echo "make docker-run      run ./zygarde in a privileged container (local smoke test)"

generate:
	$(GO) generate ./...

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

clean:
	rm -rf zygarde dist

docker-image:
	docker build -q -t $(IMAGE) build/

docker-generate: docker-image
	$(DOCKER) $(GO) generate ./...

docker-dist: docker-image
	$(DOCKER) make dist

docker-build: docker-image
	$(DOCKER) make build

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

.PHONY: vm-image vm-upstream vm-distro vm-report

vm-image:
	docker build -q -t zygarde-vmtest -f build/vmtest.Dockerfile build/

vm-upstream: docker-build vm-image
	$(VMTEST) bash test/vm/upstream.sh $(KERNELS)
	$(VMTEST) go run ./test/vm/report test/vm/out

vm-distro: docker-dist vm-image
	$(VMTEST) bash test/vm/distro.sh $(DISTROS)
	$(VMTEST) go run ./test/vm/report test/vm/out

vm-report:
	$(VMTEST) go run ./test/vm/report test/vm/out
