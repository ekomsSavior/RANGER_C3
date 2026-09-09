#!/bin/bash
# deploy.sh - Deploy Ranger C3 with Nginx fronting (optional)
set -e

VERSION="3.0.0"

echo " Ranger C3 v${VERSION} - Deploy Script "
echo "==========================================="

# Check for Go
if ! command -v go &>/dev/null; then
    echo "[-] Go not found. Install: apt install golang-go"
    exit 1
fi

# Build
echo "[*] Building binaries..."
make build 2>/dev/null || go build -ldflags="-s -w" -o build/ranger-c2 ./cmd/c2

# Create data directory
mkdir -p data

# Generate certs if needed
if [ ! -f certs/c2-cert.pem ]; then
    echo "[*] Generating TLS certificates..."
    mkdir -p certs
    ./build/ranger-c2 --gen-certs --listen :4443 --password "" --db data/c2.db 2>/dev/null || true
fi

echo ""
echo "[+] Build complete. To start:"
echo ""
echo "  # Standalone C2"
echo "  ./build/ranger-c2 \\"
echo "    --listen :4443 \\"
echo "    --password \"YOUR_PASSWORD\" \\"
echo "    --db data/c2.db \\"
echo "    --gen-certs"
echo ""
echo "  # C2 with mesh peers"
echo "  ./build/ranger-c2 \\"
echo "    --listen :4443 \\"
echo "    --mesh :9000 \\"
echo "    --bootstrap \"10.0.0.2:9000,10.0.0.3:9000\" \\"
echo "    --password \"YOUR_PASSWORD\" \\"
echo "    --db data/c2.db \\"
echo "    --gen-certs"
echo ""
echo "  # Dashboard: https://your-c2:4443/dashboard"
echo "  # Implant:   ./build/implant --c2 wss://your-c2:4443/ws"
echo ""
echo "==========================================="
