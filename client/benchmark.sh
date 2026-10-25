#!/bin/bash
set -e

# Teljesítmény- és kapacitásmérő benchmark szkript

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/go.mod" ]; then
    CLIENT_DIR="$SCRIPT_DIR"
    PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    PROJECT_DIR="$SCRIPT_DIR"
    CLIENT_DIR="$PROJECT_DIR/client"
fi

# Alapértelmezett benchmark paraméterek
NUM_VOTERS=1000
NUM_CANDIDATES=3
CONCURRENCY=25
BATCH_REG=""
RUN_TALLY=""
FORCE_RESET="-reset"
PEER_POLICY="round-robin"
OUTPUT_FILE="benchmark_results.json"

# Parancssori argumentumok feldolgozása
print_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -n, --voters <int>       Number of voters to benchmark (default: 1000)"
    echo "  -k, --candidates <int>   Number of candidates in election (default: 3)"
    echo "  -c, --concurrency <int>  Worker concurrency level (default: 25)"
    echo "  --batch                  Use batch registration (registerVoters) instead of individual"
    echo "  --batch-size <int>       Batch size for batch registration mode (default: 100)"
    echo "  --peer <policy>          Target peer policy: 'round-robin', 'peer0', or 'sdk' (default: round-robin)"
    echo "  --no-reset               Do not reset ledger state (re-use existing election)"
    echo "  --tally                  Automatically execute homomorphic tally and threshold decryption after voting"
    echo "  -o, --output <file>      JSON report output path (default: benchmark_results.json)"
    echo "  -h, --help               Display this help message"
    echo ""
    echo "Examples:"
    echo "  $0                       # Run full 1000-voter benchmark with 25 workers (3 candidates)"
    echo "  $0 -k 10 -n 1000         # Run 10-candidate election with 1000 voters"
    echo "  $0 -n 500 -c 20          # Run 500 voters with 20 concurrent workers"
    echo "  $0 --tally               # Run 1000 voters and verify tally at the end"
    exit 0
}

BATCH_SIZE_ARG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--voters)
            NUM_VOTERS="$2"
            shift 2
            ;;
        -k|--candidates)
            NUM_CANDIDATES="$2"
            shift 2
            ;;
        -c|--concurrency)
            CONCURRENCY="$2"
            shift 2
            ;;
        --batch)
            BATCH_REG="-batch-reg"
            shift
            ;;
        --batch-size)
            BATCH_SIZE_ARG="-batch-size $2"
            shift 2
            ;;
        --peer)
            PEER_POLICY="$2"
            shift 2
            ;;
        --no-reset)
            FORCE_RESET=""
            shift
            ;;
        --tally)
            RUN_TALLY="-tally"
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            ;;
    esac
done

echo "=================================================================="
echo "    TimeFabric E-Voting End-to-End Performance Benchmark         "
echo "=================================================================="

# 1. Futó konténerek ellenőrzése
echo "[*] Checking Hyperledger Fabric containers..."
CONTAINERS=("orderer.voting.com" "peer0.org1.voting.com" "peer1.org1.voting.com" "peer2.org1.voting.com" "peer3.org1.voting.com" "peer4.org1.voting.com" "peer5.org1.voting.com")
STOPPED_CONTAINERS=()

for c in "${CONTAINERS[@]}"; do
    if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        STOPPED_CONTAINERS+=("$c")
    fi
done

if [ ${#STOPPED_CONTAINERS[@]} -gt 0 ]; then
    echo "[*] Starting stopped containers: ${STOPPED_CONTAINERS[*]}..."
    docker start "${STOPPED_CONTAINERS[@]}" > /dev/null
    sleep 3
fi

# 2. Kliens bináris fordítása szükség esetén
if [ ! -f "$CLIENT_DIR/bin/client" ] || [ "$CLIENT_DIR/benchmark.go" -nt "$CLIENT_DIR/bin/client" ] || [ "$CLIENT_DIR/main.go" -nt "$CLIENT_DIR/bin/client" ]; then
    echo "[*] Building unified client binary via Docker golang:1.19..."
    mkdir -p "$CLIENT_DIR/bin"
    docker run --rm \
        -v "$CLIENT_DIR":/client \
        -w /client \
        golang:1.19 go build -o bin/client .
    cd "$CLIENT_DIR/bin" && ln -sf client trustees && ln -sf client main && ln -sf client tally && ln -sf client benchmark && cd "$CLIENT_DIR"
    echo "[+] Client binary compiled successfully."
fi

# 3. Benchmark futtatása
cd "$CLIENT_DIR"
echo "[*] Launching benchmark from $CLIENT_DIR..."
echo ""

./bin/client benchmark \
    -voters "$NUM_VOTERS" \
    -candidates "$NUM_CANDIDATES" \
    -concurrency "$CONCURRENCY" \
    -peer "$PEER_POLICY" \
    -output "$OUTPUT_FILE" \
    $BATCH_REG \
    $BATCH_SIZE_ARG \
    $RUN_TALLY \
    $FORCE_RESET

echo ""
echo "=================================================================="
echo "    [+] BENCHMARK COMPLETED SUCCESSFULLY!"
echo "=================================================================="
