#!/bin/bash
set -e

# Főkönyv ürítése: ClearAllVotes meghívása

PROJECT_DIR=$HOME/only-go-voting-project
export PATH=$PROJECT_DIR/bin:$PATH
export FABRIC_CFG_PATH=$PROJECT_DIR
export CORE_PEER_MSPCONFIGPATH=$PROJECT_DIR/crypto-config/peerOrganizations/org1.voting.com/users/Admin@org1.voting.com/msp
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_ADDRESS=localhost:7051

echo "[*] Invoking ClearAllVotes on 'mychannel'..."
./bin/peer chaincode invoke \
  -o localhost:7050 \
  -C mychannel \
  -n voting \
  -c '{"Args":["ClearAllVotes"]}'

echo "[+] Ledger state cleared successfully!"