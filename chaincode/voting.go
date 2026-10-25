package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
)

var (
	curve = elliptic.P256()
	q     = curve.Params().N
	p     = curve.Params().P
	Gx    = curve.Params().Gx
	Gy    = curve.Params().Gy
	expP4 = new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(1)), 2)
)

type ECPoint struct {
	X string `json:"x,omitempty"`
	Y string `json:"y,omitempty"`
}

func (pt ECPoint) MarshalJSON() ([]byte, error) {
	if pt.X == "" && pt.Y == "" {
		return json.Marshal("")
	}
	clean := strings.TrimPrefix(pt.X, "0x")
	if len(clean) == 66 {
		return json.Marshal(clean)
	}
	x, _ := parseBigInt(pt.X)
	y, _ := parseBigInt(pt.Y)
	if x == nil || y == nil || (x.Sign() == 0 && y.Sign() == 0) {
		return json.Marshal("00")
	}
	b := make([]byte, 33)
	if y.Bit(0) == 0 {
		b[0] = 0x02
	} else {
		b[0] = 0x03
	}
	xb := x.Bytes()
	copy(b[33-len(xb):], xb)
	return json.Marshal(hex.EncodeToString(b))
}

func (pt *ECPoint) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
		if s == "" || s == "00" || s == "0" {
			pt.X, pt.Y = "0", "0"
			return nil
		}
		x, y, err := decompressPointHex(s)
		if err != nil {
			return err
		}
		pt.X, pt.Y = fmt.Sprintf("0x%x", x), fmt.Sprintf("0x%x", y)
		return nil
	}
	type alias ECPoint
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	pt.X, pt.Y = a.X, a.Y
	return nil
}

type CiphertextComponent struct {
	A ECPoint `json:"a"`
	B ECPoint `json:"b"`
}

type BallotCiphertext []CiphertextComponent

type NIZKProof struct {
	Challenges []string   `json:"challenges"`
	Responses  [][]string `json:"responses"`
}

type VoterSignature struct {
	R string `json:"r"`
	S string `json:"s"`
}

type BallotSubmission struct {
	ElectionID string           `json:"electionId"`
	VoterPK    string           `json:"voterPk"`
	Ciphertext BallotCiphertext `json:"ciphertext"`
	Proof      NIZKProof        `json:"proof"`
	Signature  VoterSignature   `json:"signature"`
}

type EAMember struct {
	ID   int     `json:"id"`
	Name string  `json:"name"`
	Y_i  ECPoint `json:"y_i"`
}

type ElectionState struct {
	ElectionID          string     `json:"electionId"`
	Status              string     `json:"status"`
	Candidates          []string   `json:"candidates"`
	Rho                 int        `json:"rho"`
	GlobalPubKey        ECPoint    `json:"globalPubKey"`
	EAMembers           []EAMember `json:"eaMembers"`
	Threshold           int        `json:"threshold"`
	TStart              int64      `json:"tStart"`
	TEnd                int64      `json:"tEnd"`
	AcceptedBallotCount int        `json:"acceptedBallotCount"`
	TotalEligibleVoters int        `json:"totalEligibleVoters"`
}

type VoterRecord struct {
	VoterPK    string `json:"voterPk"`
	Eligible   bool   `json:"eligible"`
	HasVoted   bool   `json:"hasVoted"`
	BallotHash string `json:"ballotHash,omitempty"`
	CastTime   int64  `json:"castTime,omitempty"`
}

type BallotRecord struct {
	TxID       string           `json:"txId"`
	ElectionID string           `json:"electionId"`
	VoterPK    string           `json:"voterPk"`
	Ciphertext BallotCiphertext `json:"ciphertext"`
	Proof      NIZKProof        `json:"proof"`
	BallotHash string           `json:"ballotHash"`
	Timestamp  int64            `json:"timestamp"`
}

type DecryptionShareProof struct {
	A ECPoint `json:"a"`
	B ECPoint `json:"b"`
	Z string  `json:"z"`
}

type CandidateDecryptionShare struct {
	CandidateIndex int                  `json:"candidateIndex"`
	D_ij           ECPoint              `json:"d_ij"`
	Proof          DecryptionShareProof `json:"proof"`
}

type AuthorityDecryptionSubmission struct {
	ElectionID  string                     `json:"electionId"`
	AuthorityID int                        `json:"authorityId"`
	Shares      []CandidateDecryptionShare `json:"shares"`
}

type AggregatedTally struct {
	ElectionID  string                `json:"electionId"`
	BallotCount int                   `json:"ballotCount"`
	Totals      []CiphertextComponent `json:"totals"`
}

type FinalResultSubmission struct {
	ElectionID string  `json:"electionId"`
	Results    []int64 `json:"results"`
}

type ElectionResults struct {
	ElectionID string           `json:"electionId"`
	Results    map[string]int64 `json:"results"`
	TotalVotes int64            `json:"totalVotes"`
	Status     string           `json:"status"`
}

type VotingChaincode struct{}

func getTrustedTime(stub shim.ChaincodeStubInterface) (int64, error) {
	if ts, err := stub.GetTxTimestamp(); err == nil && ts != nil && ts.GetSeconds() > 0 {
		return ts.GetSeconds(), nil
	}
	return time.Now().Unix(), nil
}

func decompressPointHex(s string) (*big.Int, *big.Int, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if s == "" || s == "00" || s == "0" {
		return big.NewInt(0), big.NewInt(0), nil
	}
	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, nil, err
	}
	if len(data) == 65 && data[0] == 4 {
		x, y := elliptic.Unmarshal(curve, data)
		return x, y, nil
	}
	x := new(big.Int).SetBytes(data[1:])
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	y2 := new(big.Int).Sub(x3, new(big.Int).Mul(big.NewInt(3), x))
	y2.Add(y2, curve.Params().B).Mod(y2, p)

	y := new(big.Int).Exp(y2, expP4, p)
	if y.Bit(0) != uint(data[0]&1) {
		y.Sub(p, y)
	}
	return x, y, nil
}

func parseBigInt(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	clean := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	bi, ok := new(big.Int).SetString(clean, 16)
	if !ok {
		bi, ok = new(big.Int).SetString(s, 10)
	}
	if !ok {
		return nil, fmt.Errorf("invalid int: %s", s)
	}
	return bi, nil
}

func parsePoint(pt ECPoint) (*big.Int, *big.Int, error) {
	cleanX := strings.TrimPrefix(strings.TrimSpace(pt.X), "0x")
	if len(cleanX) == 66 {
		return decompressPointHex(cleanX)
	}
	x, _ := parseBigInt(pt.X)
	y, _ := parseBigInt(pt.Y)
	if x == nil || y == nil || (x.Sign() == 0 && y.Sign() == 0) {
		return big.NewInt(0), big.NewInt(0), nil
	}
	return x, y, nil
}

func pointToECPoint(x, y *big.Int) ECPoint {
	if x == nil || y == nil || (x.Sign() == 0 && y.Sign() == 0) {
		return ECPoint{X: "0", Y: "0"}
	}
	return ECPoint{X: fmt.Sprintf("0x%x", x), Y: fmt.Sprintf("0x%x", y)}
}

func pointSub(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x2 == nil || y2 == nil || (x2.Sign() == 0 && y2.Sign() == 0) {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}
	nx, ny := new(big.Int).Set(x2), new(big.Int).Sub(p, y2)
	if x1 == nil || y1 == nil || (x1.Sign() == 0 && y1.Sign() == 0) {
		return nx, ny
	}
	return curve.Add(x1, y1, nx, ny)
}

func parseVoterPubKey(pkStr string) (*ecdsa.PublicKey, error) {
	cleanHex := strings.TrimPrefix(strings.TrimSpace(pkStr), "0x")
	if b, err := hex.DecodeString(cleanHex); err == nil {
		if len(b) == 33 {
			if x, y, err := decompressPointHex(cleanHex); err == nil {
				return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
			}
		} else if len(b) == 65 {
			x, y := elliptic.Unmarshal(curve, b)
			return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
		}
	}
	var pt ECPoint
	if err := json.Unmarshal([]byte(pkStr), &pt); err == nil {
		x, y, _ := parsePoint(pt)
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}
	return nil, fmt.Errorf("invalid voter pk: %s", pkStr)
}

func computeBallotHash(electionID, voterPK string, ciphertext BallotCiphertext, proof NIZKProof) string {
	h := sha256.New()
	h.Write([]byte(electionID + voterPK))
	cBytes, _ := json.Marshal(ciphertext)
	h.Write(cBytes)
	pBytes, _ := json.Marshal(proof)
	h.Write(pBytes)
	return hex.EncodeToString(h.Sum(nil))
}

func (t *VotingChaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	_, args := stub.GetFunctionAndParameters()
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		return t.initElection(stub, args)
	}
	bytes, _ := json.Marshal(ElectionState{ElectionID: "ELECTION_DEFAULT", Status: "INITIALIZED", Threshold: 2})
	stub.PutState("Election", bytes)
	return shim.Success([]byte("Voting system initialized successfully"))
}

func (t *VotingChaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	fn, args := stub.GetFunctionAndParameters()
	switch fn {
	case "Init":
		return t.Init(stub)
	case "initElection", "setupElection":
		return t.initElection(stub, args)
	case "registerVoter":
		return t.registerVoter(stub, args)
	case "registerVoters":
		return t.registerVoters(stub, args)
	case "startVoting":
		return t.startVoting(stub, args)
	case "castBallot":
		return t.castBallot(stub, args)
	case "tallyVotes":
		return t.tallyVotes(stub)
	case "submitDecryptionShare":
		return t.submitDecryptionShare(stub, args)
	case "finalizeTally":
		return t.finalizeTally(stub, args)
	case "getElection":
		return t.getElection(stub)
	case "getVoter":
		return t.getVoter(stub, args)
	case "getBallot":
		return t.getBallot(stub, args)
	case "getBallots":
		return t.getBallots(stub)
	case "getTally":
		return t.getTally(stub)
	case "getDecryptionShares":
		return t.getDecryptionShares(stub)
	case "getResults":
		return t.getResults(stub)
	case "queryTime":
		return t.queryTime(stub)
	case "queryAll":
		return t.queryAll(stub)
	case "ClearAllVotes":
		return t.ClearAllVotes(stub)
	default:
		return shim.Error(fmt.Sprintf("Invalid function name: '%s'", fn))
	}
}

func (t *VotingChaincode) initElection(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	var state ElectionState
	if err := json.Unmarshal([]byte(args[0]), &state); err != nil {
		return shim.Error(err.Error())
	}
	if state.ElectionID == "" {
		state.ElectionID = "ELECTION_1"
	}
	state.Rho = len(state.Candidates)
	if state.Threshold < 1 {
		state.Threshold = 2
	}
	state.Status = "INITIALIZED"
	stateBytes, _ := json.Marshal(state)
	stub.PutState("Election", stateBytes)
	return shim.Success([]byte(fmt.Sprintf("Election '%s' initialized with %d candidates and threshold %d", state.ElectionID, state.Rho, state.Threshold)))
}

func (t *VotingChaincode) registerVoter(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	voterPK := strings.TrimSpace(args[0])
	if len(args) >= 2 {
		voterPK = strings.TrimSpace(args[1])
	}
	voterKey := "VOTER_" + voterPK
	if ex, _ := stub.GetState(voterKey); ex != nil {
		return shim.Error("Voter already registered")
	}
	b, _ := json.Marshal(VoterRecord{VoterPK: voterPK, Eligible: true, HasVoted: false})
	stub.PutState(voterKey, b)
	return shim.Success([]byte("Voter registered successfully"))
}

func (t *VotingChaincode) registerVoters(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	var pks []string
	json.Unmarshal([]byte(args[0]), &pks)
	count := 0
	for _, pk := range pks {
		voterKey := "VOTER_" + strings.TrimSpace(pk)
		if ex, _ := stub.GetState(voterKey); ex == nil {
			b, _ := json.Marshal(VoterRecord{VoterPK: strings.TrimSpace(pk), Eligible: true, HasVoted: false})
			stub.PutState(voterKey, b)
			count++
		}
	}
	return shim.Success([]byte(fmt.Sprintf("Registered %d new voters", count)))
}

func (t *VotingChaincode) startVoting(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	stateBytes, _ := stub.GetState("Election")
	var state ElectionState
	json.Unmarshal(stateBytes, &state)
	state.Status = "VOTING"
	b, _ := json.Marshal(state)
	stub.PutState("Election", b)
	return shim.Success([]byte("Voting phase started"))
}

func (t *VotingChaincode) castBallot(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	var sub BallotSubmission
	if len(args) == 1 {
		json.Unmarshal([]byte(args[0]), &sub)
	} else {
		sub.VoterPK = args[0]
		json.Unmarshal([]byte(args[1]), &sub.Ciphertext)
		json.Unmarshal([]byte(args[2]), &sub.Proof)
		json.Unmarshal([]byte(args[3]), &sub.Signature)
	}

	stateBytes, _ := stub.GetState("Election")
	var state ElectionState
	json.Unmarshal(stateBytes, &state)
	rho := state.Rho

	voterKey := "VOTER_" + sub.VoterPK
	voterBytes, _ := stub.GetState(voterKey)
	if voterBytes == nil {
		return shim.Error("Voter is not eligible or not registered")
	}
	var voterRec VoterRecord
	json.Unmarshal(voterBytes, &voterRec)
	if !voterRec.Eligible || voterRec.HasVoted {
		return shim.Error("Voter not eligible or already voted")
	}

	voterPubKey, err := parseVoterPubKey(sub.VoterPK)
	if err != nil {
		return shim.Error(err.Error())
	}
	sigR, _ := parseBigInt(sub.Signature.R)
	sigS, _ := parseBigInt(sub.Signature.S)
	ballotHashStr := computeBallotHash(state.ElectionID, sub.VoterPK, sub.Ciphertext, sub.Proof)
	sigHashBytes, _ := hex.DecodeString(ballotHashStr)
	if !ecdsa.Verify(voterPubKey, sigHashBytes, sigR, sigS) {
		return shim.Error("Invalid voter ECDSA signature on ballot")
	}

	A_x, A_y := make([]*big.Int, rho), make([]*big.Int, rho)
	B_x, B_y := make([]*big.Int, rho), make([]*big.Int, rho)
	for i := 0; i < rho; i++ {
		A_x[i], A_y[i], _ = parsePoint(sub.Ciphertext[i].A)
		B_x[i], B_y[i], _ = parsePoint(sub.Ciphertext[i].B)
	}
	Yx, Yy, _ := parsePoint(state.GlobalPubKey)

	// 1-a-rho-ból Chaum-Pedersen NIZKP ellenőrzése
	c_k := make([]*big.Int, rho)
	sumC := big.NewInt(0)
	for k := 0; k < rho; k++ {
		ck, _ := parseBigInt(sub.Proof.Challenges[k])
		c_k[k] = new(big.Int).Mod(ck, q)
		sumC.Add(sumC, c_k[k])
	}
	sumC.Mod(sumC, q)

	h := sha256.New()
	h.Write([]byte(state.ElectionID + sub.VoterPK + fmt.Sprintf("%d", rho)))
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
			Qx, Qy := B_x[i], B_y[i]
			if k == i {
				Qx, Qy = pointSub(B_x[i], B_y[i], Gx, Gy)
			}
			zk, _ := parseBigInt(sub.Proof.Responses[k][i])
			zk.Mod(zk, q)

			zGx, zGy := curve.ScalarBaseMult(zk.Bytes())
			cAx, cAy := curve.ScalarMult(A_x[i], A_y[i], c_k[k].Bytes())
			Ux, Uy := pointSub(zGx, zGy, cAx, cAy)

			zYx, zYy := curve.ScalarMult(Yx, Yy, zk.Bytes())
			cQx, cQy := curve.ScalarMult(Qx, Qy, c_k[k].Bytes())
			Vx, Vy := pointSub(zYx, zYy, cQx, cQy)

			h.Write(Ux.Bytes())
			h.Write(Uy.Bytes())
			h.Write(Vx.Bytes())
			h.Write(Vy.Bytes())
		}
	}
	expectedC := new(big.Int).Mod(new(big.Int).SetBytes(h.Sum(nil)), q)
	if sumC.Cmp(expectedC) != 0 {
		return shim.Error("Invalid 1-out-of-rho NIZKP proof! Challenge sum equation does not hold.")
	}

	currentTime, _ := getTrustedTime(stub)
	txID := stub.GetTxID()
	voterRec.HasVoted = true
	voterRec.BallotHash = ballotHashStr
	voterRec.CastTime = currentTime
	updatedVoterBytes, _ := json.Marshal(voterRec)
	stub.PutState(voterKey, updatedVoterBytes)

	ballotBytes, _ := json.Marshal(BallotRecord{
		TxID:       txID,
		ElectionID: state.ElectionID,
		VoterPK:    sub.VoterPK,
		Ciphertext: sub.Ciphertext,
		Proof:      sub.Proof,
		BallotHash: ballotHashStr,
		Timestamp:  currentTime,
	})
	stub.PutState("BALLOT_"+txID, ballotBytes)
	stub.PutState("BALLOT_HASH_"+ballotHashStr, []byte(txID))

	receiptBytes, _ := json.Marshal(map[string]interface{}{
		"status":     "ACCEPTED",
		"txId":       txID,
		"ballotHash": ballotHashStr,
		"timestamp":  currentTime,
	})
	return shim.Success(receiptBytes)
}

func (t *VotingChaincode) tallyVotes(stub shim.ChaincodeStubInterface) peer.Response {
	stateBytes, _ := stub.GetState("Election")
	var state ElectionState
	json.Unmarshal(stateBytes, &state)
	rho := state.Rho

	C1_star_x, C1_star_y := make([]*big.Int, rho), make([]*big.Int, rho)
	C2_star_x, C2_star_y := make([]*big.Int, rho), make([]*big.Int, rho)

	iter, err := stub.GetStateByRange("BALLOT_", "BALLOT_~")
	if err != nil {
		return shim.Error(err.Error())
	}
	defer iter.Close()

	ballotCount := 0
	for iter.HasNext() {
		item, _ := iter.Next()
		if strings.HasPrefix(item.Key, "BALLOT_HASH_") {
			continue
		}
		var bRec BallotRecord
		if err := json.Unmarshal(item.Value, &bRec); err != nil || len(bRec.Ciphertext) != rho {
			continue
		}
		ballotCount++
		for j := 0; j < rho; j++ {
			ax, ay, _ := parsePoint(bRec.Ciphertext[j].A)
			bx, by, _ := parsePoint(bRec.Ciphertext[j].B)
			if C1_star_x[j] == nil {
				C1_star_x[j], C1_star_y[j] = ax, ay
				C2_star_x[j], C2_star_y[j] = bx, by
			} else {
				C1_star_x[j], C1_star_y[j] = curve.Add(C1_star_x[j], C1_star_y[j], ax, ay)
				C2_star_x[j], C2_star_y[j] = curve.Add(C2_star_x[j], C2_star_y[j], bx, by)
			}
		}
	}

	tally := AggregatedTally{ElectionID: state.ElectionID, BallotCount: ballotCount, Totals: make([]CiphertextComponent, rho)}
	for j := 0; j < rho; j++ {
		tally.Totals[j] = CiphertextComponent{
			A: pointToECPoint(C1_star_x[j], C1_star_y[j]),
			B: pointToECPoint(C2_star_x[j], C2_star_y[j]),
		}
	}
	tallyBytes, _ := json.Marshal(tally)
	stub.PutState("AggregatedTally", tallyBytes)

	state.AcceptedBallotCount = ballotCount
	state.Status = "TALLY_COMPLETED"
	updatedStateBytes, _ := json.Marshal(state)
	stub.PutState("Election", updatedStateBytes)
	return shim.Success(tallyBytes)
}

func (t *VotingChaincode) submitDecryptionShare(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	var sub AuthorityDecryptionSubmission
	if err := json.Unmarshal([]byte(args[0]), &sub); err != nil {
		return shim.Error(err.Error())
	}
	stateBytes, _ := stub.GetState("Election")
	var state ElectionState
	json.Unmarshal(stateBytes, &state)

	var eaMember *EAMember
	for idx := range state.EAMembers {
		if state.EAMembers[idx].ID == sub.AuthorityID {
			eaMember = &state.EAMembers[idx]
			break
		}
	}
	if eaMember == nil {
		return shim.Error(fmt.Sprintf("Authority ID %d is not registered", sub.AuthorityID))
	}

	tallyBytes, _ := stub.GetState("AggregatedTally")
	var tally AggregatedTally
	json.Unmarshal(tallyBytes, &tally)
	Y_i_x, Y_i_y, _ := parsePoint(eaMember.Y_i)

	// DLEQ bizonyítások ellenőrzése
	for j := 0; j < state.Rho; j++ {
		share := sub.Shares[j]
		Dij_x, Dij_y, _ := parsePoint(share.D_ij)
		C1_x, C1_y, _ := parsePoint(tally.Totals[j].A)
		Ax, Ay, _ := parsePoint(share.Proof.A)
		Bx, By, _ := parsePoint(share.Proof.B)
		zProof, _ := parseBigInt(share.Proof.Z)
		zProof.Mod(zProof, q)

		ph := sha256.New()
		for _, pt := range []*big.Int{Gx, Gy, C1_x, C1_y, Y_i_x, Y_i_y, Dij_x, Dij_y, Ax, Ay, Bx, By} {
			ph.Write(pt.Bytes())
		}
		cProof := new(big.Int).Mod(new(big.Int).SetBytes(ph.Sum(nil)), q)

		zG_x, zG_y := curve.ScalarBaseMult(zProof.Bytes())
		cY_x, cY_y := curve.ScalarMult(Y_i_x, Y_i_y, cProof.Bytes())
		r1_x, r1_y := curve.Add(Ax, Ay, cY_x, cY_y)
		if zG_x.Cmp(r1_x) != 0 || zG_y.Cmp(r1_y) != 0 {
			return shim.Error(fmt.Sprintf("DLEQ check 1 failed for candidate %d", j))
		}

		zC1_x, zC1_y := curve.ScalarMult(C1_x, C1_y, zProof.Bytes())
		cD_x, cD_y := curve.ScalarMult(Dij_x, Dij_y, cProof.Bytes())
		r2_x, r2_y := curve.Add(Bx, By, cD_x, cD_y)
		if zC1_x.Cmp(r2_x) != 0 || zC1_y.Cmp(r2_y) != 0 {
			return shim.Error(fmt.Sprintf("DLEQ check 2 failed for candidate %d", j))
		}
	}

	stub.PutState(fmt.Sprintf("DECRYPTION_SHARE_%d", sub.AuthorityID), []byte(args[0]))
	return shim.Success([]byte(fmt.Sprintf("Decryption shares from Authority %d verified and accepted", sub.AuthorityID)))
}

func (t *VotingChaincode) finalizeTally(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	var sub FinalResultSubmission
	if err := json.Unmarshal([]byte(args[0]), &sub); err != nil {
		return shim.Error(err.Error())
	}
	stateBytes, _ := stub.GetState("Election")
	var state ElectionState
	json.Unmarshal(stateBytes, &state)
	rho := state.Rho

	tallyBytes, _ := stub.GetState("AggregatedTally")
	var tally AggregatedTally
	json.Unmarshal(tallyBytes, &tally)

	var S []int
	activeShares := make(map[int][]CandidateDecryptionShare)
	for _, ea := range state.EAMembers {
		if len(S) == state.Threshold {
			break
		}
		shareBytes, _ := stub.GetState(fmt.Sprintf("DECRYPTION_SHARE_%d", ea.ID))
		if shareBytes != nil {
			var sSub AuthorityDecryptionSubmission
			if err := json.Unmarshal(shareBytes, &sSub); err == nil && len(sSub.Shares) == rho {
				S = append(S, ea.ID)
				activeShares[ea.ID] = sSub.Shares
			}
		}
	}
	if len(S) < state.Threshold {
		return shim.Error(fmt.Sprintf("Insufficient authority shares submitted: %d available, %d required", len(S), state.Threshold))
	}

	// Lagrange-interpoláció a 0 pontban
	lambdas := make(map[int]*big.Int)
	for _, i := range S {
		num, den := big.NewInt(1), big.NewInt(1)
		for _, k := range S {
			if k == i {
				continue
			}
			num.Mul(num, big.NewInt(int64(k))).Mod(num, q)
			diff := big.NewInt(int64(k - i))
			diff.Mod(diff, q)
			if diff.Sign() < 0 {
				diff.Add(diff, q)
			}
			den.Mul(den, diff).Mod(den, q)
		}
		lambdas[i] = new(big.Int).Mod(new(big.Int).Mul(num, new(big.Int).ModInverse(den, q)), q)
	}

	var totalVotes int64 = 0
	resultMap := make(map[string]int64)

	for j := 0; j < rho; j++ {
		Tj := sub.Results[j]
		totalVotes += Tj

		var Dj_x, Dj_y *big.Int
		for idx, i := range S {
			Dij_x, Dij_y, _ := parsePoint(activeShares[i][j].D_ij)
			term_x, term_y := curve.ScalarMult(Dij_x, Dij_y, lambdas[i].Bytes())
			if idx == 0 {
				Dj_x, Dj_y = term_x, term_y
			} else {
				Dj_x, Dj_y = curve.Add(Dj_x, Dj_y, term_x, term_y)
			}
		}

		// M_j^* = C_{2,j}^* - D_j
		C2_x, C2_y, _ := parsePoint(tally.Totals[j].B)
		Mj_x, Mj_y := pointSub(C2_x, C2_y, Dj_x, Dj_y)

		// Diszkrét logaritmus ellenőrzése: T_j * G == M_j^*
		if Tj == 0 {
			if Mj_x != nil && Mj_y != nil && (Mj_x.Sign() != 0 || Mj_y.Sign() != 0) {
				return shim.Error(fmt.Sprintf("Candidate %d claimed 0 votes, but M_%d^* != PointAtInfinity", j, j))
			}
		} else {
			exp_x, exp_y := curve.ScalarBaseMult(big.NewInt(Tj).Bytes())
			if exp_x.Cmp(Mj_x) != 0 || exp_y.Cmp(Mj_y) != 0 {
				return shim.Error(fmt.Sprintf("Discrete log check failed for candidate %d: %d*G != M_%d^*", j, Tj, j))
			}
		}
		resultMap[state.Candidates[j]] = Tj
	}

	finalRes := ElectionResults{
		ElectionID: state.ElectionID,
		Results:    resultMap,
		TotalVotes: totalVotes,
		Status:     "FINISHED",
	}
	resBytes, _ := json.Marshal(finalRes)
	stub.PutState("ElectionResults", resBytes)

	state.Status = "FINISHED"
	updatedStateBytes, _ := json.Marshal(state)
	stub.PutState("Election", updatedStateBytes)
	return shim.Success(resBytes)
}

func (t *VotingChaincode) getElection(stub shim.ChaincodeStubInterface) peer.Response {
	val, err := stub.GetState("Election")
	if err != nil || val == nil {
		return shim.Error("Election not initialized")
	}
	return shim.Success(val)
}

func (t *VotingChaincode) getVoter(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	val, err := stub.GetState("VOTER_" + strings.TrimSpace(args[0]))
	if err != nil || val == nil {
		return shim.Error("Voter not found")
	}
	return shim.Success(val)
}

func (t *VotingChaincode) getBallot(stub shim.ChaincodeStubInterface, args []string) peer.Response {
	key := strings.TrimSpace(args[0])
	if val, _ := stub.GetState("BALLOT_" + key); val != nil {
		return shim.Success(val)
	}
	if txId, _ := stub.GetState("BALLOT_HASH_" + key); txId != nil {
		if val, _ := stub.GetState("BALLOT_" + string(txId)); val != nil {
			return shim.Success(val)
		}
	}
	return shim.Error("Ballot not found")
}

func (t *VotingChaincode) getBallots(stub shim.ChaincodeStubInterface) peer.Response {
	iter, err := stub.GetStateByRange("BALLOT_", "BALLOT_~")
	if err != nil {
		return shim.Error(err.Error())
	}
	defer iter.Close()

	var ballots []BallotRecord
	for iter.HasNext() {
		item, _ := iter.Next()
		if strings.HasPrefix(item.Key, "BALLOT_HASH_") {
			continue
		}
		var b BallotRecord
		if err := json.Unmarshal(item.Value, &b); err == nil {
			ballots = append(ballots, b)
		}
	}
	bytes, _ := json.Marshal(ballots)
	return shim.Success(bytes)
}

func (t *VotingChaincode) getTally(stub shim.ChaincodeStubInterface) peer.Response {
	val, _ := stub.GetState("AggregatedTally")
	if val == nil {
		return shim.Error("Aggregated tally not found")
	}
	return shim.Success(val)
}

func (t *VotingChaincode) getDecryptionShares(stub shim.ChaincodeStubInterface) peer.Response {
	iter, err := stub.GetStateByRange("DECRYPTION_SHARE_", "DECRYPTION_SHARE_~")
	if err != nil {
		return shim.Error(err.Error())
	}
	defer iter.Close()

	var shares []AuthorityDecryptionSubmission
	for iter.HasNext() {
		item, _ := iter.Next()
		var s AuthorityDecryptionSubmission
		if err := json.Unmarshal(item.Value, &s); err == nil {
			shares = append(shares, s)
		}
	}
	bytes, _ := json.Marshal(shares)
	return shim.Success(bytes)
}

func (t *VotingChaincode) getResults(stub shim.ChaincodeStubInterface) peer.Response {
	val, _ := stub.GetState("ElectionResults")
	if val == nil {
		return shim.Error("Final results not yet published")
	}
	return shim.Success(val)
}

func (t *VotingChaincode) queryTime(stub shim.ChaincodeStubInterface) peer.Response {
	tNow, _ := getTrustedTime(stub)
	return shim.Success([]byte(fmt.Sprintf("%d", tNow)))
}

func (t *VotingChaincode) queryAll(stub shim.ChaincodeStubInterface) peer.Response {
	iter, err := stub.GetStateByRange("", "")
	if err != nil {
		return shim.Error(err.Error())
	}
	defer iter.Close()

	type kv struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	var list []kv
	for iter.HasNext() {
		item, _ := iter.Next()
		list = append(list, kv{Key: item.Key, Value: string(item.Value)})
	}
	b, _ := json.Marshal(list)
	return shim.Success(b)
}

func (t *VotingChaincode) ClearAllVotes(stub shim.ChaincodeStubInterface) peer.Response {
	iter, err := stub.GetStateByRange("", "")
	if err != nil {
		return shim.Error(err.Error())
	}
	defer iter.Close()

	for iter.HasNext() {
		item, _ := iter.Next()
		stub.DelState(item.Key)
	}
	fmt.Println("Ledger Cleared: All election state removed.")
	return shim.Success([]byte("Ledger cleared successfully"))
}

func main() {
	if err := shim.Start(new(VotingChaincode)); err != nil {
		fmt.Printf("Error starting Voting Chaincode: %s\n", err)
	}
}
