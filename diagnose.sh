#!/usr/bin/env bash
# Linux / macOS launcher for the ISP / NAT TCP idle-timeout diagnostic tool.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
    exec python3 "$SCRIPT_DIR/nat_idle_diag.py" "$@"
elif command -v python >/dev/null 2>&1; then
    exec python "$SCRIPT_DIR/nat_idle_diag.py" "$@"
else
    echo "Error: python3 is required to run nat_idle_diag.py." >&2
    echo "Install it via your package manager (e.g., 'sudo apt install python3')." >&2
    exit 1
fi
