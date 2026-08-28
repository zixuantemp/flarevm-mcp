#!/bin/bash
# FlareVM MCP installer for Kali Linux
set -e

echo "[*] FlareVM MCP installer"

# 1. Check Python
if ! command -v python3 >/dev/null; then echo "Python 3.10+ required"; exit 1; fi

# 2. Create venv (or use existing)
VENV="${VENV:-/home/$USER/.flarevm-mcp/venv}"
mkdir -p "$(dirname "$VENV")"
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e .

# 3. Check smbclient
command -v smbclient >/dev/null || {
    echo "[!] smbclient missing - install with: sudo apt install smbclient"
}

# 4. Prompt for FlareVM credentials -> keyring
echo
echo "Enter FlareVM credentials (stored in system keyring):"
IP="${FLAREVM_HOST:-}"
while [ -z "$IP" ]; do read -p "  FlareVM IP (required): " IP; done
read -p "  FlareVM user [xtemp]: " USER_; USER_=${USER_:-xtemp}
read -sp "  FlareVM password: " PW; echo
"$VENV/bin/python" -c "import keyring; keyring.set_password('flarevm', '$USER_', '$PW')"

# 5. Generate MCP config snippet
cat <<EOF

[*] Installation complete.

Add this to your MCP client config (~/.claude.json, a project .mcp.json, or claude_desktop_config.json):

{
  "mcpServers": {
    "flarevm": {
      "command": "$VENV/bin/python",
      "args": ["$(pwd)/server.py"],
      "env": {
        "FLAREVM_HOST": "$IP",
        "FLAREVM_USER": "$USER_"
      }
    }
  }
}
EOF
