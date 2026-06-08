#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTCAP_NAME="extcap_esp32c6_zigsniff.py"

if [[ "$(uname -s)" == "Darwin" ]]; then
    EXTCAP_DIR="${HOME}/.wireshark/extcap"
else
    EXTCAP_DIR="${HOME}/.local/lib/wireshark/extcap"
fi

mkdir -p "${EXTCAP_DIR}"
install -m 755 "${SCRIPT_DIR}/${EXTCAP_NAME}" "${EXTCAP_DIR}/${EXTCAP_NAME}"

echo "Installed ${EXTCAP_NAME} to ${EXTCAP_DIR}"
echo "Restart Wireshark or use Capture -> Refresh Interfaces (F5)."
