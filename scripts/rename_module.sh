#!/usr/bin/env bash
# scripts/rename_module.sh
# Safely renames the Go module path and updates all internal imports
# when the repository is renamed away from OnionScan.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CURRENT_MODULE=$(grep '^module ' "${ROOT_DIR}/go.mod" | awk '{print $2}')

if [ $# -ne 1 ]; then
    echo "Usage: $0 <new-module-path>"
    echo "Example: $0 github.com/AryanXCode646/OnionSec"
    echo "Current module: ${CURRENT_MODULE}"
    exit 1
fi

NEW_MODULE="$1"

if [ "${NEW_MODULE}" = "${CURRENT_MODULE}" ]; then
    echo "Module is already ${NEW_MODULE}; nothing to rename."
    exit 0
fi

echo "=========================================="
echo "Renaming Go module:"
echo "  From: ${CURRENT_MODULE}"
echo "  To:   ${NEW_MODULE}"
echo "=========================================="

# 1. Update go.mod
echo "[1/4] Updating go.mod..."
sed -i "s|^module .*|module ${NEW_MODULE}|" "${ROOT_DIR}/go.mod"

# 2. Update all internal Go imports
echo "[2/4] Updating import declarations across all Go source files..."
find "${ROOT_DIR}" -name "*.go" -not -path '*/node_modules/*' -not -path '*/.git/*' | while read -r file; do
    if grep -q "${CURRENT_MODULE}" "${file}"; then
        sed -i "s|${CURRENT_MODULE}|${NEW_MODULE}|g" "${file}"
    fi
done

# 3. Format Go files
echo "[3/4] Running gofmt..."
gofmt -w "${ROOT_DIR}"

# 4. Verify compilation and tests
echo "[4/4] Verifying with go vet and go test..."
cd "${ROOT_DIR}"
go vet ./...
go test ./...

echo "=========================================="
echo "Successfully renamed module to: ${NEW_MODULE}"
echo "Run 'git diff' to review changes before committing."
echo "=========================================="
