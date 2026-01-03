#!/bin/bash
# PayloadsAllTheThings Skills Plugin Installer
# For Claude Code

set -e

PLUGIN_NAME="payloadsallthethings-skills"
PLUGIN_DIR="${HOME}/.claude/plugins/${PLUGIN_NAME}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================"
echo "PayloadsAllTheThings Skills Installer"
echo "========================================"
echo ""

# Check if Claude Code is installed
if ! command -v claude &> /dev/null; then
    echo "[WARNING] Claude Code CLI not found in PATH"
    echo "          Proceeding with manual installation..."
fi

# Create plugins directory if it doesn't exist
mkdir -p "${HOME}/.claude/plugins"

# Check if plugin already exists
if [ -d "${PLUGIN_DIR}" ]; then
    echo "[INFO] Plugin directory already exists"
    read -p "Do you want to update/reinstall? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "[INFO] Installation cancelled"
        exit 0
    fi
    rm -rf "${PLUGIN_DIR}"
fi

# Copy plugin files
echo "[INFO] Installing plugin to ${PLUGIN_DIR}"
mkdir -p "${PLUGIN_DIR}"

# Copy all files
cp -r "${SCRIPT_DIR}/skills" "${PLUGIN_DIR}/"
cp "${SCRIPT_DIR}/plugin.json" "${PLUGIN_DIR}/"
cp "${SCRIPT_DIR}/README.md" "${PLUGIN_DIR}/"
cp "${SCRIPT_DIR}/LICENSE" "${PLUGIN_DIR}/"
cp "${SCRIPT_DIR}/CLAUDE.md" "${PLUGIN_DIR}/"

# Copy settings if .claude directory exists
if [ -d "${SCRIPT_DIR}/.claude" ]; then
    mkdir -p "${PLUGIN_DIR}/.claude"
    cp -r "${SCRIPT_DIR}/.claude/"* "${PLUGIN_DIR}/.claude/"
fi

echo ""
echo "[SUCCESS] Plugin installed successfully!"
echo ""
echo "Plugin location: ${PLUGIN_DIR}"
echo ""
echo "Available skills (61 total):"
echo "  - sqli, xss, ssrf, xxe, ssti, jwt, oauth, csrf"
echo "  - command-injection, lfi-rfi, file-upload, idor"
echo "  - cors, clickjacking, prototype-pollution, nosql"
echo "  - And 45 more..."
echo ""
echo "Usage in Claude Code:"
echo "  /sqli          - SQL Injection payloads"
echo "  /xss           - XSS techniques"
echo "  /ssrf          - SSRF bypass methods"
echo ""
echo "Or ask Claude Code directly:"
echo "  'Show me SQL injection payloads for MySQL'"
echo "  'How do I bypass CORS restrictions?'"
echo ""
echo "========================================"
echo "Installation complete!"
echo "========================================"
