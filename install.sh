#!/usr/bin/env bash
set -euo pipefail

echo "Installing jev-guard..."

INSTALL_DIR="${HOME}/.jevguard/bin"
mkdir -p "${INSTALL_DIR}"
TARGET="${INSTALL_DIR}/jev-guard"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "${ARCH}" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: ${ARCH}" && exit 1 ;;
esac

if command -v go >/dev/null 2>&1 && [ -f "./main.go" ] && [ -f "./go.mod" ] && grep -qE '^module[[:space:]]+jev-guard' ./go.mod; then
  echo "Building jev-guard locally from source..."
  GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'none')"
  GIT_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  GIT_TAG="$(git describe --tags --exact-match 2>/dev/null || echo 'dev')"
  LDFLAGS="-s -w -X jev-guard/pkg/cli.Version=${GIT_TAG} -X jev-guard/pkg/cli.Commit=${GIT_COMMIT} -X jev-guard/pkg/cli.Date=${GIT_DATE}"
  go build -ldflags="${LDFLAGS}" -o "${TARGET}" ./main.go
else
  REPO="${GITHUB_REPOSITORY:-ClemensSchartmueller/jev-guard}"
  DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/jev-guard-${OS}-${ARCH}"
  echo "Downloading ${DOWNLOAD_URL}..."
  curl -fsSL "${DOWNLOAD_URL}" -o "${TARGET}"
fi

chmod +x "${TARGET}"

if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
  echo "Notice: ${INSTALL_DIR} is not in your PATH."
  echo "Add 'export PATH=\"\$HOME/.jevguard/bin:\$PATH\"' to your ~/.bashrc or ~/.zshrc."
fi

echo "jev-guard successfully installed at ${TARGET}"
