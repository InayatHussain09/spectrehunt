#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$HOME/.local/bin}"

mkdir -p "$BIN"
cat > "$BIN/spectrehunt" <<EOF
#!/usr/bin/env bash
exec python3 "$ROOT/main.py" "\$@"
EOF
chmod +x "$BIN/spectrehunt"
echo "[+] installed $BIN/spectrehunt -> $ROOT/main.py"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "[!] add to PATH:  export PATH=\"$BIN:\$PATH\"" ;;
esac
