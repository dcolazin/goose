#!/usr/bin/env bash
set -eu

GOOSE_VERSION="${GOOSE_VERSION:-v1.61.0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  GOOSE_ARCH="x86_64" ;;
    aarch64) GOOSE_ARCH="aarch64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

FILE="goose-${GOOSE_ARCH}-unknown-linux-musl.tar.bz2"
URL="https://github.com/aaif-goose/goose/releases/download/${GOOSE_VERSION}/${FILE}"

echo "Downloading ${URL}..."
curl -sLf "$URL" -o "${SCRIPT_DIR}/${FILE}"
tar -xjf "${SCRIPT_DIR}/${FILE}" -C "${SCRIPT_DIR}"
rm "${SCRIPT_DIR}/${FILE}"

echo "goose ${GOOSE_VERSION} ready at ${SCRIPT_DIR}/goose"