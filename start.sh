#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "=========================================================="
echo " Starting Lab PDF Signature Sentinel Service"
echo "=========================================================="

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "[+] Docker detected. Launching container via docker compose..."
    docker compose up --build -d
    echo ""
    echo "[✓] Service is running in background!"
    echo "    Web Portal:    http://localhost:8000"
    echo "    API Swagger:   http://localhost:8000/docs"
    echo "    View Logs:     docker compose logs -f"
    echo "    Stop Service:  docker compose down"
else
    echo "[!] Docker not found or daemon not running. Falling back to local Python..."
    if [ ! -d ".venv" ]; then
        echo "[+] Creating virtual environment .venv..."
        python3 -m venv .venv
        . .venv/bin/activate
        pip install --upgrade pip
        pip install -r requirements.txt
    else
        . .venv/bin/activate
    fi
    PORT="${PORT:-8001}"
    echo "[+] Starting Uvicorn on 0.0.0.0:${PORT}..."
    uvicorn app.main:app --host 0.0.0.0 --port "${PORT}" --reload
fi
