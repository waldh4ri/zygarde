# VM test harness: boots kernels with QEMU and runs zygarde inside them.
#  - upstream kernels: cilium/ci-kernels images via vimto (KVM)
#  - distribution kernels: official cloud images via cloud-init (test/vm/distro.sh);
#    arm64 images are emulated (TCG), so they boot slower
# Run privileged so /dev/kvm is available.
FROM golang:1.25-trixie
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      qemu-system-x86 qemu-system-arm qemu-efi-aarch64 qemu-utils \
      cloud-image-utils xorriso jq curl ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
RUN CGO_ENABLED=0 GOBIN=/usr/local/bin go install lmb.io/vimto@v0.4.0
WORKDIR /src
