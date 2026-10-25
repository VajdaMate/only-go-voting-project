#!/bin/bash
set -e

# Opcionális kezdeti konfiguráció (ElectionConfig JSON vagy üres)
INIT_PARAM=${1:-""}

echo "=== Starting Full TimeFabric Cold Boot (6-Member Election Authority) ==="

# --- 1. Configuration ---
PROJECT_DIR=$HOME/only-go-voting-project
CC_PATH="$PROJECT_DIR/chaincode"
export PATH=$PROJECT_DIR/bin:$PATH
export FABRIC_CFG_PATH=$PROJECT_DIR
export GOPATH=$PROJECT_DIR
export COMPOSE_PROJECT_NAME=only-go-voting-project
export CORE_PEER_MSPCONFIGPATH=$PROJECT_DIR/crypto-config/peerOrganizations/org1.voting.com/users/Admin@org1.voting.com/msp
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_ADDRESS=localhost:7051

# Docker Compose parancs detektálása (v1 vs v2)
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    DOCKER_COMPOSE="docker compose"
fi

# --- 2. Deep Cleanup ---
echo "[*] Cleaning up Docker containers and volumes..."
docker rm -f $(docker ps -aq) 2>/dev/null || true
docker rmi -f $(docker images "dev-peer*" -q) 2>/dev/null || true
docker network prune -f 2>/dev/null || true
docker volume prune -f 2>/dev/null || true

echo "[*] Removing old cryptographic materials and artifacts..."
cd $PROJECT_DIR
sudo rm -rf crypto-config channel-artifacts genesisblock *.cds *.block *.tar.gz chaincode/vendor chaincode/go.mod chaincode/go.sum
echo "1.0" > .cc_version

# --- 3. Generate Artifacts ---
echo "[*] Generating crypto materials for Orderer and 6 Election Authority Peers..."
./bin/cryptogen generate --config=./crypto-config.yaml
mkdir -p channel-artifacts

echo "[*] Generating Genesis Block..."
./bin/configtxgen -profile VotingGenesis -channelID system-channel -outputBlock ./genesisblock

echo "[*] Generating Channel Transaction..."
./bin/configtxgen -profile VotingChannel -outputCreateChannelTx ./channel-artifacts/channel.tx -channelID mychannel

# --- 4. Launch Network ---
echo "[*] Launching TimeFabric network via $DOCKER_COMPOSE..."
$DOCKER_COMPOSE up -d
echo "Waiting 30 seconds for Orderer and 6 Peers to initialize..."
sleep 30

# --- 5. Channel Creation & Join (All 6 Peers) ---
echo "[*] Creating channel 'mychannel'..."
./bin/peer channel create -o localhost:7050 -c mychannel -f ./channel-artifacts/channel.tx

PEER_PORTS=(7051 8051 9051 10051 11051 12051)
for i in "${!PEER_PORTS[@]}"; do
    PORT=${PEER_PORTS[$i]}
    echo "[*] Joining peer${i}.org1.voting.com (localhost:${PORT}) to 'mychannel'..."
    CORE_PEER_ADDRESS=localhost:${PORT} ./bin/peer channel join -b mychannel.block
done

# --- 6. Chaincode Deployment ---
echo "[*] Packaging Chaincode (v1.0) via Docker (Pure Go, no CGO)..."
docker run --rm \
  -v $(pwd)/chaincode:/opt/gopath/src/voting \
  -v $(pwd):/opt/gopath/src/github.com/hyperledger/fabric \
  -w /opt/gopath/src/github.com/hyperledger/fabric \
  -e GO111MODULE=off \
  hyperledger/fabric-tools:1.4.12 \
  peer chaincode package -n voting -v 1.0 -p voting voting_v1.0.cds

sudo chown -R $USER:$USER $PROJECT_DIR

for i in "${!PEER_PORTS[@]}"; do
    PORT=${PEER_PORTS[$i]}
    echo "[*] Installing Chaincode (v1.0) on peer${i}.org1.voting.com (localhost:${PORT})..."
    CORE_PEER_ADDRESS=localhost:${PORT} ./bin/peer chaincode install voting_v1.0.cds
done

echo "[*] Instantiating Chaincode (v1.0) on 'mychannel'..."
CORE_PEER_ADDRESS=localhost:7051 ./bin/peer chaincode instantiate \
  -o localhost:7050 \
  -C mychannel \
  -n voting \
  -v 1.0 \
  -c "{\"Args\":[\"Init\", \"${INIT_PARAM}\"]}" \
  -P "OR('Org1MSP.member')"

echo ""
echo "========================================================"
echo " TimeFabric Network (6 EA Nodes) Successfully Booted!"
if [ -n "${INIT_PARAM}" ]; then
    echo " Initialized with config: '${INIT_PARAM}'"
else
    echo " Initialized in ready state (configure via initElection or invoke)"
fi
echo "========================================================"
