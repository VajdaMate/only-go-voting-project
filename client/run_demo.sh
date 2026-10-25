#!/bin/bash
set -e

CLIENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$CLIENT_DIR"

echo "=================================================================="
echo "    TimeFabric E-Voting End-to-End Client Simulation Pipeline     "
echo "    Kutatási prototípus szimulációs folyamat                      "
echo "=================================================================="

# Kliens bináris fordítása, ha még nem létezik
if [ ! -f bin/client ]; then
    echo "[*] Building unified client binary..."
    mkdir -p bin
    docker run --rm -v "$CLIENT_DIR":/client -w /client golang:1.19 go build -o bin/client .
    cd bin && ln -sf client trustees && ln -sf client main && ln -sf client tally && ln -sf client benchmark && cd ..
fi

echo ""
echo ">>> Running End-to-End Election Lifecycle (Setup -> Vote -> Tally) <<<"
./bin/client demo

echo ""
echo "=================================================================="
echo "    [+] FULL ELECTION LIFECYCLE SIMULATION SUCCESSFULLY COMPLETED! "
echo "=================================================================="
