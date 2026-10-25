#!/bin/bash
set -e

# Opcionális választási konfiguráció JSON formátumban
CONFIG_PARAM=${1:-""}

PROJECT_DIR=$HOME/only-go-voting-project
export PATH=$PROJECT_DIR/bin:$PATH
export FABRIC_CFG_PATH=$PROJECT_DIR
export CORE_PEER_MSPCONFIGPATH=$PROJECT_DIR/crypto-config/peerOrganizations/org1.voting.com/users/Admin@org1.voting.com/msp
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_ADDRESS=localhost:7051

echo "[*] Step 1: Clearing all existing votes, ballots, and registered voters..."
./bin/peer chaincode invoke \
  -o localhost:7050 \
  -C mychannel \
  -n voting \
  -c '{"Args":["ClearAllVotes"]}'

echo "[*] Waiting 3 seconds for block commit..."
sleep 3

echo "[*] Step 2: Re-initializing election state..."
./bin/peer chaincode invoke \
  -o localhost:7050 \
  -C mychannel \
  -n voting \
  -c "{\"Args\":[\"Init\", \"${CONFIG_PARAM}\"]}"

echo ""
echo "========================================================"
echo " [+] Election state successfully reset and initialized!"
if [ -n "${CONFIG_PARAM}" ]; then
    echo " Applied configuration: ${CONFIG_PARAM}"
else
    echo " Initialized in ready state."
fi
echo "========================================================"
