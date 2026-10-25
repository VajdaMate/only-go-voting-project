package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/hyperledger/fabric/core/chaincode/shim"
)

func TestFullElectionWorkflow(t *testing.T) {
	fmt.Println("=== Starting Full Chaincode Lifecycle Test ===")

	cc := new(VotingChaincode)
	stub := shim.NewMockStub("voting", cc)

	xSecret, _ := rand.Int(rand.Reader, q)
	a1, _ := rand.Int(rand.Reader, q)
	a2, _ := rand.Int(rand.Reader, q)

	Yx, Yy := curve.ScalarBaseMult(xSecret.Bytes())

	shares := make([]*big.Int, 7) // 1-indexed
	eaMembers := make([]EAMember, 6)
	for i := 1; i <= 6; i++ {
		iz := big.NewInt(int64(i))
		iz2 := new(big.Int).Mul(iz, iz)
		iz2.Mod(iz2, q)

		term1 := new(big.Int).Mul(a1, iz)
		term2 := new(big.Int).Mul(a2, iz2)

		si := new(big.Int).Add(xSecret, term1)
		si.Add(si, term2)
		si.Mod(si, q)

		shares[i] = si
		yix, yiy := curve.ScalarBaseMult(si.Bytes())
		eaMembers[i-1] = EAMember{
			ID:   i,
			Name: fmt.Sprintf("peer%d.org1.voting.com", i-1),
			Y_i:  pointToECPoint(yix, yiy),
		}
	}

	candidates := []string{"Candidate Alpha", "Candidate Beta", "Candidate Gamma"}
	rho := len(candidates) // 3

	config := ElectionState{
		ElectionID:   "MOCK_ELECTION_2026",
		Candidates:   candidates,
		Rho:          rho,
		GlobalPubKey: pointToECPoint(Yx, Yy),
		EAMembers:    eaMembers,
		Threshold:    3,
		TStart:       0,
		TEnd:         0, // 0 disables strict deadline check in mock
	}
	configBytes, _ := json.Marshal(config)

	initRes := stub.MockInit("tx0", [][]byte{[]byte("Init"), configBytes})
	if initRes.Status != shim.OK {
		t.Fatalf("Init failed: %s", initRes.Message)
	}
	fmt.Println("Election initialized on ledger.")

	voterPrivKeys := make([]*ecdsa.PrivateKey, 3)
	voterPKHexes := make([]string, 3)
	for i := 0; i < 3; i++ {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("Key gen error: %v", err)
		}
		voterPrivKeys[i] = key
		pubBytes := elliptic.Marshal(curve, key.PublicKey.X, key.PublicKey.Y)
		voterPKHexes[i] = hex.EncodeToString(pubBytes)

		regRes := stub.MockInvoke(fmt.Sprintf("reg_%d", i), [][]byte{
			[]byte("registerVoter"),
			[]byte(voterPKHexes[i]),
		})
		if regRes.Status != shim.OK {
			t.Fatalf("Register voter %d failed: %s", i, regRes.Message)
		}
	}
	fmt.Println("Registered 3 eligible voters.")

	stub.MockInvoke("start_tx", [][]byte{[]byte("startVoting")})

	votes := []int{1, 0, 1}

	for voterIdx, chosen := range votes {
		voterPK := voterPKHexes[voterIdx]
		voterPriv := voterPrivKeys[voterIdx]

		// One-Hot vektor titkosítása
		cipherComp := make(BallotCiphertext, rho)
		rScalars := make([]*big.Int, rho)
		A_x := make([]*big.Int, rho)
		A_y := make([]*big.Int, rho)
		B_x := make([]*big.Int, rho)
		B_y := make([]*big.Int, rho)

		for i := 0; i < rho; i++ {
			rScalars[i], _ = rand.Int(rand.Reader, q)
			A_x[i], A_y[i] = curve.ScalarBaseMult(rScalars[i].Bytes())

			rY_x, rY_y := curve.ScalarMult(Yx, Yy, rScalars[i].Bytes())
			if i == chosen {
				B_x[i], B_y[i] = curve.Add(Gx, Gy, rY_x, rY_y)
			} else {
				B_x[i], B_y[i] = rY_x, rY_y
			}

			cipherComp[i] = CiphertextComponent{
				A: pointToECPoint(A_x[i], A_y[i]),
				B: pointToECPoint(B_x[i], B_y[i]),
			}
		}

		// 1-a-rho-ból NIZKP előállítása
		c_k := make([]*big.Int, rho)
		z_ki := make([][]*big.Int, rho)
		for k := 0; k < rho; k++ {
			z_ki[k] = make([]*big.Int, rho)
		}

		U_x := make([][]*big.Int, rho)
		U_y := make([][]*big.Int, rho)
		V_x := make([][]*big.Int, rho)
		V_y := make([][]*big.Int, rho)
		for k := 0; k < rho; k++ {
			U_x[k] = make([]*big.Int, rho)
			U_y[k] = make([]*big.Int, rho)
			V_x[k] = make([]*big.Int, rho)
			V_y[k] = make([]*big.Int, rho)
		}

		// Szimulált ágak (k != chosen)
		for k := 0; k < rho; k++ {
			if k == chosen {
				continue
			}
			c_k[k], _ = rand.Int(rand.Reader, q)
			for i := 0; i < rho; i++ {
				z_ki[k][i], _ = rand.Int(rand.Reader, q)

				var Qx, Qy *big.Int
				if k == i {
					Qx, Qy = pointSub(B_x[i], B_y[i], Gx, Gy)
				} else {
					Qx, Qy = B_x[i], B_y[i]
				}

				zG_x, zG_y := curve.ScalarBaseMult(z_ki[k][i].Bytes())
				cA_x, cA_y := curve.ScalarMult(A_x[i], A_y[i], c_k[k].Bytes())
				U_x[k][i], U_y[k][i] = pointSub(zG_x, zG_y, cA_x, cA_y)

				zY_x, zY_y := curve.ScalarMult(Yx, Yy, z_ki[k][i].Bytes())
				cQ_x, cQ_y := curve.ScalarMult(Qx, Qy, c_k[k].Bytes())
				V_x[k][i], V_y[k][i] = pointSub(zY_x, zY_y, cQ_x, cQ_y)
			}
		}

		// Valódi ág (k == chosen)
		omega := make([]*big.Int, rho)
		for i := 0; i < rho; i++ {
			omega[i], _ = rand.Int(rand.Reader, q)
			U_x[chosen][i], U_y[chosen][i] = curve.ScalarBaseMult(omega[i].Bytes())
			V_x[chosen][i], V_y[chosen][i] = curve.ScalarMult(Yx, Yy, omega[i].Bytes())
		}

		// Fiat-Shamir kihívás számítása
		h := sha256.New()
		h.Write([]byte("MOCK_ELECTION_2026"))
		h.Write([]byte(voterPK))
		h.Write([]byte(fmt.Sprintf("%d", rho)))
		for i := 0; i < rho; i++ {
			h.Write(A_x[i].Bytes())
			h.Write(A_y[i].Bytes())
			h.Write(B_x[i].Bytes())
			h.Write(B_y[i].Bytes())
		}
		h.Write(Gx.Bytes())
		h.Write(Gy.Bytes())
		h.Write(Yx.Bytes())
		h.Write(Yy.Bytes())
		for k := 0; k < rho; k++ {
			for i := 0; i < rho; i++ {
				h.Write(U_x[k][i].Bytes())
				h.Write(U_y[k][i].Bytes())
				h.Write(V_x[k][i].Bytes())
				h.Write(V_y[k][i].Bytes())
			}
		}
		cHash := new(big.Int).SetBytes(h.Sum(nil))
		cHash.Mod(cHash, q)

		cSumOther := big.NewInt(0)
		for k := 0; k < rho; k++ {
			if k != chosen {
				cSumOther.Add(cSumOther, c_k[k])
			}
		}
		cSumOther.Mod(cSumOther, q)
		c_chosen := new(big.Int).Sub(cHash, cSumOther)
		c_chosen.Mod(c_chosen, q)
		if c_chosen.Sign() < 0 {
			c_chosen.Add(c_chosen, q)
		}
		c_k[chosen] = c_chosen

		for i := 0; i < rho; i++ {
			cr := new(big.Int).Mul(c_chosen, rScalars[i])
			cr.Mod(cr, q)
			zi := new(big.Int).Add(omega[i], cr)
			zi.Mod(zi, q)
			z_ki[chosen][i] = zi
		}

		// NIZKProof összeállítása
		proof := NIZKProof{
			Challenges: make([]string, rho),
			Responses:  make([][]string, rho),
		}
		for k := 0; k < rho; k++ {
			proof.Challenges[k] = fmt.Sprintf("0x%x", c_k[k])
			proof.Responses[k] = make([]string, rho)
			for i := 0; i < rho; i++ {
				proof.Responses[k][i] = fmt.Sprintf("0x%x", z_ki[k][i])
			}
		}

		// Választói ECDSA aláírás a szavazaton
		ballotHashStr := computeBallotHash("MOCK_ELECTION_2026", voterPK, cipherComp, proof)
		sigHashBytes, _ := hex.DecodeString(ballotHashStr)
		rSig, sSig, err := ecdsa.Sign(rand.Reader, voterPriv, sigHashBytes)
		if err != nil {
			t.Fatalf("Sign error: %v", err)
		}
		signature := VoterSignature{
			R: fmt.Sprintf("0x%x", rSig),
			S: fmt.Sprintf("0x%x", sSig),
		}

		submission := BallotSubmission{
			ElectionID: "MOCK_ELECTION_2026",
			VoterPK:    voterPK,
			Ciphertext: cipherComp,
			Proof:      proof,
			Signature:  signature,
		}
		subBytes, _ := json.Marshal(submission)

		castRes := stub.MockInvoke(fmt.Sprintf("cast_tx_%d", voterIdx), [][]byte{
			[]byte("castBallot"),
			subBytes,
		})
		if castRes.Status != shim.OK {
			t.Fatalf("Voter %d castBallot failed: %s", voterIdx, castRes.Message)
		}

			doubleRes := stub.MockInvoke(fmt.Sprintf("cast_double_%d", voterIdx), [][]byte{
			[]byte("castBallot"),
			subBytes,
		})
		if doubleRes.Status == shim.OK {
			t.Fatalf("Double voting was NOT prevented for voter %d!", voterIdx)
		}
	}
	fmt.Println("All 3 ballots cast and double-voting verified!")

	tallyRes := stub.MockInvoke("tally_tx", [][]byte{[]byte("tallyVotes")})
	if tallyRes.Status != shim.OK {
		t.Fatalf("tallyVotes failed: %s", tallyRes.Message)
	}

	var tally AggregatedTally
	json.Unmarshal(tallyRes.Payload, &tally)
	if tally.BallotCount != 3 {
		t.Fatalf("Expected 3 ballots in tally, got %d", tally.BallotCount)
	}
	fmt.Println("Homomorphic tally computed successfully on mock ledger.")

	S := []int{1, 2, 4}
	for _, authID := range S {
		si := shares[authID]
		sharesList := make([]CandidateDecryptionShare, rho)

		for j := 0; j < rho; j++ {
			C1_x, C1_y, _ := parsePoint(tally.Totals[j].A)
			Dij_x, Dij_y := curve.ScalarMult(C1_x, C1_y, si.Bytes())

			r, _ := rand.Int(rand.Reader, q)
			Ax, Ay := curve.ScalarBaseMult(r.Bytes())
			Bx, By := curve.ScalarMult(C1_x, C1_y, r.Bytes())

			yix, yiy, _ := parsePoint(eaMembers[authID-1].Y_i)

			ph := sha256.New()
			ph.Write(Gx.Bytes())
			ph.Write(Gy.Bytes())
			ph.Write(C1_x.Bytes())
			ph.Write(C1_y.Bytes())
			ph.Write(yix.Bytes())
			ph.Write(yiy.Bytes())
			ph.Write(Dij_x.Bytes())
			ph.Write(Dij_y.Bytes())
			ph.Write(Ax.Bytes())
			ph.Write(Ay.Bytes())
			ph.Write(Bx.Bytes())
			ph.Write(By.Bytes())
			cProof := new(big.Int).SetBytes(ph.Sum(nil))
			cProof.Mod(cProof, q)

			cs := new(big.Int).Mul(cProof, si)
			cs.Mod(cs, q)
			zProof := new(big.Int).Add(r, cs)
			zProof.Mod(zProof, q)

			sharesList[j] = CandidateDecryptionShare{
				CandidateIndex: j,
				D_ij:           pointToECPoint(Dij_x, Dij_y),
				Proof: DecryptionShareProof{
					A: pointToECPoint(Ax, Ay),
					B: pointToECPoint(Bx, By),
					Z: fmt.Sprintf("0x%x", zProof),
				},
			}
		}

		eaSub := AuthorityDecryptionSubmission{
			ElectionID:  "MOCK_ELECTION_2026",
			AuthorityID: authID,
			Shares:      sharesList,
		}
		eaSubBytes, _ := json.Marshal(eaSub)

		subRes := stub.MockInvoke(fmt.Sprintf("ea_tx_%d", authID), [][]byte{
			[]byte("submitDecryptionShare"),
			eaSubBytes,
		})
		if subRes.Status != shim.OK {
			t.Fatalf("submitDecryptionShare for EA %d failed: %s", authID, subRes.Message)
		}
	}
	fmt.Println("All 3 authority decryption shares submitted & verified by contract.")

	claimedCounts := []int64{1, 2, 0}
	finalSub := FinalResultSubmission{
		ElectionID: "MOCK_ELECTION_2026",
		Results:    claimedCounts,
	}
	finalSubBytes, _ := json.Marshal(finalSub)

	finRes := stub.MockInvoke("finalize_tx", [][]byte{
		[]byte("finalizeTally"),
		finalSubBytes,
	})
	if finRes.Status != shim.OK {
		t.Fatalf("finalizeTally failed: %s", finRes.Message)
	}

	var results ElectionResults
	json.Unmarshal(finRes.Payload, &results)
	if results.Results["Candidate Alpha"] != 1 || results.Results["Candidate Beta"] != 2 || results.Results["Candidate Gamma"] != 0 {
		t.Fatalf("Unexpected results: %+v", results.Results)
	}
	if results.TotalVotes != 3 {
		t.Fatalf("Expected 3 total votes, got %d", results.TotalVotes)
	}

	fmt.Printf("FINAL RESULTS VERIFIED: Candidate Alpha=%d, Candidate Beta=%d, Candidate Gamma=%d\n",
		results.Results["Candidate Alpha"], results.Results["Candidate Beta"], results.Results["Candidate Gamma"])

	queryRes := stub.MockInvoke("q_results", [][]byte{[]byte("getResults")})
	if queryRes.Status != shim.OK {
		t.Fatalf("getResults query failed: %s", queryRes.Message)
	}

	electRes := stub.MockInvoke("q_elect", [][]byte{[]byte("getElection")})
	if electRes.Status != shim.OK {
		t.Fatalf("getElection query failed: %s", electRes.Message)
	}

	ballotsRes := stub.MockInvoke("q_ballots", [][]byte{[]byte("getBallots")})
	if ballotsRes.Status != shim.OK {
		t.Fatalf("getBallots query failed: %s", ballotsRes.Message)
	}

	fmt.Println("=== FULL LIFECYCLE TEST PASSED! ===")
}
