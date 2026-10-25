#!/bin/bash
set -e

INIT_PARAM=${1:-""}
PROJECT_DIR=$HOME/only-go-voting-project
cd $PROJECT_DIR

export PATH=$PROJECT_DIR/bin:$PATH
export FABRIC_CFG_PATH=$PROJECT_DIR
export CORE_PEER_MSPCONFIGPATH=$PROJECT_DIR/crypto-config/peerOrganizations/org1.voting.com/users/Admin@org1.voting.com/msp
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_ADDRESS=localhost:7051

# Verziószám automatikus növelése (pl. 1.0 -> 1.1)
if [ ! -f .cc_version ]; then
    echo "1.0" > .cc_version
fi
CURRENT_VER=$(cat .cc_version)
NEW_VER=$(awk -v v="$CURRENT_VER" 'BEGIN {printf "%.1f", v + 0.1}')
echo "$NEW_VER" > .cc_version

echo "=== Upgrading Chaincode from v${CURRENT_VER} to v${NEW_VER} ==="

echo "[*] Packaging Chaincode (v${NEW_VER}) via Docker (Pure Go)..."
docker run --rm \
  -u $(id -u):$(id -g) \
  -e HOME=/tmp \
  -v $(pwd)/chaincode:/opt/gopath/src/voting \
  -v $(pwd):/opt/gopath/src/github.com/hyperledger/fabric \
  -w /opt/gopath/src/github.com/hyperledger/fabric \
  -e GO111MODULE=off \
  hyperledger/fabric-tools:1.4.12 \
  peer chaincode package -n voting -v ${NEW_VER} -p voting voting_v${NEW_VER}.cds

PEER_PORTS=(7051 8051 9051 10051 11051 12051)
for i in "${!PEER_PORTS[@]}"; do
    PORT=${PEER_PORTS[$i]}
    echo "[*] Installing Chaincode (v${NEW_VER}) on peer${i}.org1.voting.com (localhost:${PORT})..."
    CORE_PEER_ADDRESS=localhost:${PORT} ./bin/peer chaincode install voting_v${NEW_VER}.cds
done

echo "[*] Upgrading Chaincode on channel 'mychannel' to v${NEW_VER}..."
CORE_PEER_ADDRESS=localhost:7051 ./bin/peer chaincode upgrade \
  -o localhost:7050 \
  -C mychannel \
  -n voting \
  -v ${NEW_VER} \
  -c "{\"Args\":[\"Init\", \"${INIT_PARAM}\"]}" \
  -P "OR('Org1MSP.member')"

echo ""
echo "========================================================"
echo " [+] Chaincode successfully upgraded to v${NEW_VER}!"
echo "========================================================"
