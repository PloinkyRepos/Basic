#!/bin/sh
set -eu

image="${BWRAP_RUNNER_IMAGE:-assistos/bwrap-runner:node24-bookworm}"

if command -v podman >/dev/null 2>&1; then
    runtime=podman
elif command -v docker >/dev/null 2>&1; then
    runtime=docker
else
    echo "bwrap-runner image build requires podman or docker in PATH." >&2
    exit 1
fi

if "$runtime" image inspect "$image" >/dev/null 2>&1; then
    echo "[bwrap-runner] image already available: $image"
    exit 0
fi

cd "$(dirname "$0")/.."
echo "[bwrap-runner] building image $image with $runtime"
exec "$runtime" build -t "$image" -f Dockerfile .
