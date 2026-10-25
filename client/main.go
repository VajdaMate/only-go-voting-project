package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"

	"timefabric-client/crypto"
)

var eaPeerPairs = [][]string{
	{"peer0.org1.voting.com", "peer1.org1.voting.com"},
	{"peer2.org1.voting.com", "peer3.org1.voting.com"},
	{"peer4.org1.voting.com", "peer5.org1.voting.com"},
}

func getChannelClient() (*fabsdk.FabricSDK, *channel.Client, error) {
	configPath := "./connection.yaml"
	sdk, err := fabsdk.New(config.FromFile(configPath))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SDK: %v", err)
	}
	clientContext := sdk.ChannelContext("mychannel", fabsdk.WithUser("Admin"), fabsdk.WithOrg("Org1"))
	client, err := channel.New(clientContext)
	if err != nil {
		sdk.Close()
		return nil, nil, fmt.Errorf("failed to create channel client: %v", err)
	}
	return sdk, client, nil
}

func runSetup(client *channel.Client) {
	fmt.Println("=================================================================")
	fmt.Println("  Phase 0: Election Setup & Decentralized Key Generation (DKG)  ")
	fmt.Println("  Simulating 6 Independent Election Authorities (EAs)            ")
	fmt.Println("  BFT Threshold: n=6, f=1 => t = f + 1 = 2                       ")
	fmt.Println("=================================================================")

	totalEAs := 6
	threshold := 2
	candidates := []string{"Alice Johnson", "Bob Smith", "Charlie Brown"}
	electionID := "TimeFabric_Election_2026"

	fmt.Printf("[*] Setting up election '%s' with %d candidates...\n", electionID, len(candidates))
	for idx, cand := range candidates {
		fmt.Printf("    [%d] %s\n", idx, cand)
	}

	xSecret, Yx, Yy, shares, Yix, Yiy, err := crypto.SimulateDKG(totalEAs, threshold)
	if err != nil {
		log.Fatalf("DKG simulation failed: %v", err)
	}
	_ = xSecret

	globalPubKey := crypto.PointToECPoint(Yx, Yy)
	fmt.Printf("[+] Global Public Key Y (Compressed): %s\n", crypto.CompressPointHex(Yx, Yy))

	eaMembers := make([]crypto.EAMember, totalEAs)
	for i := 1; i <= totalEAs; i++ {
		eaName := fmt.Sprintf("peer%d.org1.voting.com", i-1)
		pubKeyShare := crypto.PointToECPoint(Yix[i], Yiy[i])

		eaMembers[i-1] = crypto.EAMember{
			ID:   i,
			Name: eaName,
			Y_i:  pubKeyShare,
		}

		shareFile := crypto.TrusteeShareFile{
			AuthorityID: i,
			Name:        fmt.Sprintf("EA-%d (%s)", i, eaName),
			SecretShare: fmt.Sprintf("%064x", shares[i]),
			PubKeyShare: pubKeyShare,
			GlobalPub:   globalPubKey,
			Threshold:   threshold,
			TotalEAs:    totalEAs,
		}

		filename := fmt.Sprintf("trustee_%d_share.json", i)
		jsonData, _ := json.MarshalIndent(shareFile, "", "  ")
		if err := os.WriteFile(filename, jsonData, 0644); err != nil {
			log.Fatalf("Failed to save %s: %v", filename, err)
		}
		fmt.Printf("    -> Saved key share to %s (%s)\n", filename, eaName)
	}

	fmt.Println("[*] Resetting existing ledger state...")
	_, _ = client.Execute(channel.Request{
		ChaincodeID: "voting",
		Fcn:         "ClearAllVotes",
		Args:        [][]byte{},
	}, channel.WithTargetEndpoints("peer0.org1.voting.com", "peer1.org1.voting.com"))

	electionConfig := crypto.ElectionState{
		ElectionID:   electionID,
		Status:       "INITIALIZED",
		Candidates:   candidates,
		Rho:          len(candidates),
		GlobalPubKey: globalPubKey,
		EAMembers:    eaMembers,
		Threshold:    threshold,
	}

	configBytes, _ := json.Marshal(electionConfig)
	fmt.Println("[*] Invoking 'initElection' on blockchain...")
	response, err := client.Execute(channel.Request{
		ChaincodeID: "voting",
		Fcn:         "initElection",
		Args:        [][]byte{configBytes},
	}, channel.WithTargetEndpoints("peer0.org1.voting.com", "peer1.org1.voting.com"))

	if err != nil {
		log.Fatalf("Failed to initialize election: %v", err)
	}

	fmt.Printf("[+] Success! TxID: %s, Response: %s\n", response.TransactionID[:10], string(response.Payload))
	fmt.Println("=== Phase 0 Complete: Initialized with Threshold t=2 ===")
}

func registerVoter(client *channel.Client, name string, privKey *ecdsa.PrivateKey, pairIdx int) {
	pubHex := crypto.CompressPointHex(privKey.PublicKey.X, privKey.PublicKey.Y)
	targets := eaPeerPairs[pairIdx%len(eaPeerPairs)]

	resp, err := client.Execute(channel.Request{
		ChaincodeID: "voting",
		Fcn:         "registerVoter",
		Args:        [][]byte{[]byte(pubHex)},
	}, channel.WithTargetEndpoints(targets...))

	if err != nil {
		log.Fatalf("Failed to register %s: %v", name, err)
	}
	fmt.Printf("    -> Registered %s (VoterPK: %s... TxID: %s)\n", name, pubHex[:18], resp.TransactionID[:10])
}

func castVote(client *channel.Client, name string, privKey *ecdsa.PrivateKey, chosenCandidate int, election crypto.ElectionState, Yx, Yy *big.Int, pairIdx int) {
	voterPKHex := crypto.CompressPointHex(privKey.PublicKey.X, privKey.PublicKey.Y)

	ciphertext, rScalars, Ax, Ay, Bx, By, err := crypto.EncryptBallot(chosenCandidate, election.Rho, Yx, Yy)
	if err != nil {
		log.Fatalf("[%s] Failed to encrypt ballot: %v", name, err)
	}

	proof, err := crypto.GenerateNIZKP(election.ElectionID, voterPKHex, chosenCandidate, election.Rho, Ax, Ay, Bx, By, rScalars, Yx, Yy)
	if err != nil {
		log.Fatalf("[%s] Failed to generate NIZKP: %v", name, err)
	}

	signature, err := crypto.SignBallot(privKey, election.ElectionID, voterPKHex, ciphertext, proof)
	if err != nil {
		log.Fatalf("[%s] Failed to sign ballot: %v", name, err)
	}

	submission := crypto.BallotSubmission{
		ElectionID: election.ElectionID,
		VoterPK:    voterPKHex,
		Ciphertext: ciphertext,
		Proof:      proof,
		Signature:  signature,
	}

	subBytes, _ := json.Marshal(submission)
	targets := eaPeerPairs[pairIdx%len(eaPeerPairs)]
	fmt.Printf("    -> %s casting ballot for Candidate [%d] (%s) [Payload: %d bytes]...\n",
		name, chosenCandidate, election.Candidates[chosenCandidate], len(subBytes))

	resp, err := client.Execute(channel.Request{
		ChaincodeID: "voting",
		Fcn:         "castBallot",
		Args:        [][]byte{subBytes},
	}, channel.WithTargetEndpoints(targets...))

	if err != nil {
		fmt.Printf("       [BLOCKED] Smart contract rejected transaction: %v\n", err)
	} else {
		var receipt map[string]interface{}
		json.Unmarshal(resp.Payload, &receipt)
		fmt.Printf("       [SUCCESS] Ballot accepted! BallotHash: %v (TxID: %s)\n", receipt["ballotHash"], resp.TransactionID[:10])
	}
}

func runVote(client *channel.Client) {
	fmt.Println("=================================================================")
	fmt.Println("  Phase 1 & 2: Voter Registration & Anonymous Ballot Casting     ")
	fmt.Println("  1-out-of-rho NIZKP & EC-ElGamal Homomorphic Encryption         ")
	fmt.Println("=================================================================")

	queryResp, err := client.Query(channel.Request{
		ChaincodeID: "voting",
		Fcn:         "getElection",
		Args:        [][]byte{},
	}, channel.WithTargetEndpoints("peer0.org1.voting.com"))
	if err != nil {
		log.Fatalf("Failed to query getElection: %v (Run setup first)", err)
	}

	var election crypto.ElectionState
	json.Unmarshal(queryResp.Payload, &election)
	if election.Rho < 2 {
		log.Fatalf("Election not properly initialized. Run setup first.")
	}

	Yx, Yy, _ := crypto.ParsePoint(election.GlobalPubKey)
	fmt.Printf("[+] Synced with Election '%s' (Candidates: %d, Threshold: %d)\n", election.ElectionID, election.Rho, election.Threshold)

	alicePriv, _ := ecdsa.GenerateKey(crypto.Curve, rand.Reader)
	bobPriv, _ := ecdsa.GenerateKey(crypto.Curve, rand.Reader)
	charliePriv, _ := ecdsa.GenerateKey(crypto.Curve, rand.Reader)

	fmt.Println("[*] Registering eligible voters...")
	registerVoter(client, "Alice", alicePriv, 0)
	registerVoter(client, "Bob", bobPriv, 1)
	registerVoter(client, "Charlie", charliePriv, 2)

	time.Sleep(1 * time.Second)

	fmt.Println("[*] Activating Voting Phase...")
	_, _ = client.Execute(channel.Request{
		ChaincodeID: "voting",
		Fcn:         "startVoting",
		Args:        [][]byte{},
	}, channel.WithTargetEndpoints("peer0.org1.voting.com", "peer1.org1.voting.com"))

	fmt.Println("[*] Casting encrypted and signed ballots...")
	castVote(client, "Alice", alicePriv, 1, election, Yx, Yy, 0)
	castVote(client, "Bob", bobPriv, 0, election, Yx, Yy, 1)
	castVote(client, "Charlie", charliePriv, 1, election, Yx, Yy, 2)

	time.Sleep(1 * time.Second)

	fmt.Println("[*] Testing double-voting prevention (Alice attempts to re-vote)...")
	castVote(client, "Alice (Double Vote Attempt)", alicePriv, 2, election, Yx, Yy, 0)

	fmt.Println("=== Phase 1 & 2 Complete! Ballots secured on ledger ===")
}

func runTally(client *channel.Client) {
	fmt.Println("=================================================================")
	fmt.Println("  Phase 3-5: Homomorphic Tallying & Threshold Decryption         ")
	fmt.Println("  Reconstruction with t=2 EA Shares                              ")
	fmt.Println("=================================================================")

	queryResp, err := client.Query(channel.Request{
		ChaincodeID: "voting",
		Fcn:         "getElection",
		Args:        [][]byte{},
	}, channel.WithTargetEndpoints("peer0.org1.voting.com"))
	if err != nil {
		log.Fatalf("Failed to query election: %v", err)
	}

	var election crypto.ElectionState
	json.Unmarshal(queryResp.Payload, &election)
	rho := election.Rho
	threshold := election.Threshold
	if threshold < 1 {
		threshold = 2
	}

	fmt.Println("[*] Triggering Homomorphic Tallying on Ledger...")
	tallyResp, err := client.Execute(channel.Request{
		ChaincodeID: "voting",
		Fcn:         "tallyVotes",
		Args:        [][]byte{},
	}, channel.WithTargetEndpoints("peer0.org1.voting.com", "peer1.org1.voting.com"))
	if err != nil {
		log.Fatalf("tallyVotes failed: %v", err)
	}

	var tally crypto.AggregatedTally
	json.Unmarshal(tallyResp.Payload, &tally)
	fmt.Printf("[+] Homomorphic tally complete. Ballots aggregated: %d\n", tally.BallotCount)

	participatingIDs := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		participatingIDs[i] = i + 1
	}

	activeShareMap := make(map[int][]crypto.CandidateDecryptionShare)
	for _, id := range participatingIDs {
		filename := fmt.Sprintf("trustee_%d_share.json", id)
		fileBytes, err := os.ReadFile(filename)
		if err != nil {
			log.Fatalf("Failed to read %s: %v", filename, err)
		}

		var sFile crypto.TrusteeShareFile
		json.Unmarshal(fileBytes, &sFile)
		secretShareInt, _ := crypto.ParseBigInt(sFile.SecretShare)

		sub, err := crypto.GeneratePartialDecryption(election.ElectionID, id, secretShareInt, tally.Totals, sFile.PubKeyShare)
		if err != nil {
			log.Fatalf("Failed to generate partial decryption for EA %d: %v", id, err)
		}
		activeShareMap[id] = sub.Shares

		subBytes, _ := json.Marshal(sub)
		peerA := fmt.Sprintf("peer%d.org1.voting.com", (id-1)%6)
		peerB := fmt.Sprintf("peer%d.org1.voting.com", id%6)

		shareResp, err := client.Execute(channel.Request{
			ChaincodeID: "voting",
			Fcn:         "submitDecryptionShare",
			Args:        [][]byte{subBytes},
		}, channel.WithTargetEndpoints(peerA, peerB))
		if err != nil {
			log.Fatalf("submitDecryptionShare failed for EA %d: %v", id, err)
		}
		fmt.Printf("    -> EA-%d partial decryption verified by contract: %s\n", id, string(shareResp.Payload))
	}

	fmt.Println("[*] Computing Lagrange interpolation and solving discrete log...")
	lambdas, _ := crypto.ComputeLagrangeCoefficients(participatingIDs)
	recoveredTallies := make([]int64, rho)
	N := int64(tally.BallotCount)

	for j := 0; j < rho; j++ {
		var Dj_x, Dj_y *big.Int
		for idx, id := range participatingIDs {
			dij_x, dij_y, _ := crypto.ParsePoint(activeShareMap[id][j].D_ij)
			term_x, term_y := crypto.Curve.ScalarMult(dij_x, dij_y, lambdas[id].Bytes())
			if idx == 0 {
				Dj_x, Dj_y = term_x, term_y
			} else {
				Dj_x, Dj_y = crypto.Curve.Add(Dj_x, Dj_y, term_x, term_y)
			}
		}

		C2_x, C2_y, _ := crypto.ParsePoint(tally.Totals[j].B)
		Mj_x, Mj_y := crypto.PointSub(C2_x, C2_y, Dj_x, Dj_y)

		Tj, err := crypto.SolveDiscreteLog(Mj_x, Mj_y, N)
		if err != nil {
			log.Fatalf("Discrete log failed for %s: %v", election.Candidates[j], err)
		}
		recoveredTallies[j] = Tj
		fmt.Printf("    -> %s: %d votes\n", election.Candidates[j], Tj)
	}

	finalSub := crypto.FinalResultSubmission{
		ElectionID: election.ElectionID,
		Results:    recoveredTallies,
	}
	finalSubBytes, _ := json.Marshal(finalSub)

	finResp, err := client.Execute(channel.Request{
		ChaincodeID: "voting",
		Fcn:         "finalizeTally",
		Args:        [][]byte{finalSubBytes},
	}, channel.WithTargetEndpoints("peer0.org1.voting.com", "peer1.org1.voting.com"))
	if err != nil {
		log.Fatalf("finalizeTally failed: %v", err)
	}

	var results crypto.ElectionResults
	json.Unmarshal(finResp.Payload, &results)

	fmt.Println("\n=================================================================")
	fmt.Println("             OFFICIAL VERIFIED ELECTION RESULTS                  ")
	fmt.Println("=================================================================")
	fmt.Printf("Election ID    : %s\n", results.ElectionID)
	fmt.Printf("Total Ballots  : %d\n", results.TotalVotes)
	fmt.Printf("Ledger Status  : %s\n", results.Status)
	for _, candName := range election.Candidates {
		fmt.Printf("  • %-20s : %d vote(s)\n", candName, results.Results[candName])
	}
	fmt.Println("=================================================================")
}

func runClear(client *channel.Client) {
	fmt.Println("[*] Clearing all election data from ledger...")
	resp, err := client.Execute(channel.Request{
		ChaincodeID: "voting",
		Fcn:         "ClearAllVotes",
		Args:        [][]byte{},
	}, channel.WithTargetEndpoints("peer0.org1.voting.com", "peer1.org1.voting.com"))
	if err != nil {
		log.Fatalf("Failed to clear ledger: %v", err)
	}
	fmt.Printf("[+] Ledger cleared successfully! TxID: %s\n", resp.TransactionID)
}

func printUsage() {
	fmt.Println("Usage: client <command> [arguments]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  setup        Initialize election & generate DKG key shares")
	fmt.Println("  vote         Register voters and cast encrypted ballots")
	fmt.Println("  tally        Compute homomorphic tally and reconstruct results")
	fmt.Println("  demo         Run end-to-end election lifecycle (setup -> vote -> tally)")
	fmt.Println("  clear        Reset all ledger election state")
	fmt.Println("  benchmark    Run comprehensive performance benchmark suite")
	fmt.Println("")
}

func main() {
	cmd := "demo"
	var subArgs []string

	baseName := filepath.Base(os.Args[0])
	if strings.Contains(baseName, "benchmark") {
		runBenchmark(os.Args[1:])
		return
	}
	if strings.Contains(baseName, "trustees") {
		cmd = "setup"
	} else if strings.Contains(baseName, "tally") {
		cmd = "tally"
	} else if len(os.Args) > 1 {
		cmd = os.Args[1]
		subArgs = os.Args[2:]
	}

	if cmd == "benchmark" {
		runBenchmark(subArgs)
		return
	}

	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		printUsage()
		return
	}

	sdk, client, err := getChannelClient()
	if err != nil {
		log.Fatalf("[-] Connection error: %v", err)
	}
	defer sdk.Close()

	switch cmd {
	case "setup":
		runSetup(client)
	case "vote":
		runVote(client)
	case "tally":
		runTally(client)
	case "clear":
		runClear(client)
	case "demo":
		runSetup(client)
		time.Sleep(1 * time.Second)
		runVote(client)
		time.Sleep(1 * time.Second)
		runTally(client)
	default:
		fmt.Printf("Unknown command: '%s'\n\n", cmd)
		printUsage()
	}
}
