package crypto

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ECPoint struct {
	X string `json:"x,omitempty"`
	Y string `json:"y,omitempty"`
}

func (pt ECPoint) MarshalJSON() ([]byte, error) {
	if pt.X == "" && pt.Y == "" {
		return json.Marshal("")
	}
	cleanX := strings.TrimPrefix(pt.X, "0x")
	if len(cleanX) == 66 && (strings.HasPrefix(cleanX, "02") || strings.HasPrefix(cleanX, "03")) {
		return json.Marshal(cleanX)
	}
	x, errX := ParseBigInt(pt.X)
	y, errY := ParseBigInt(pt.Y)
	if errX != nil || errY != nil {
		type alias ECPoint
		return json.Marshal(alias(pt))
	}
	if IsPointAtInfinity(x, y) {
		return json.Marshal("00")
	}
	return json.Marshal(CompressPointHex(x, y))
}

func (pt *ECPoint) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "\"") && strings.HasSuffix(trimmed, "\"") {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		s = strings.TrimSpace(s)
		if s == "" || s == "00" || s == "0" {
			pt.X = "0"
			pt.Y = "0"
			return nil
		}
		x, y, err := DecompressPointHex(s)
		if err != nil {
			return err
		}
		pt.X = fmt.Sprintf("0x%x", x)
		pt.Y = fmt.Sprintf("0x%x", y)
		return nil
	}
	type alias ECPoint
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	pt.X = a.X
	pt.Y = a.Y
	return nil
}

type CiphertextComponent struct {
	A ECPoint `json:"a"`
	B ECPoint `json:"b"`
}

type BallotCiphertext []CiphertextComponent

type NIZKProof struct {
	Challenges []string   `json:"challenges"` // c_k (length rho, 32-byte hex scalars)
	Responses  [][]string `json:"responses"`  // z_{k,i} (matrix rho x rho, 32-byte hex scalars)
}

type VoterSignature struct {
	R string `json:"r"` // 32-byte hex scalar
	S string `json:"s"` // 32-byte hex scalar
}

type BallotSubmission struct {
	ElectionID string           `json:"electionId"`
	VoterPK    string           `json:"voterPk"` // 33-byte compressed hex string (SEC 1)
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
	TotalEligibleVoters int        `json:"totalEligibleVoters"`
	AcceptedBallotCount int        `json:"acceptedBallotCount"`
}

type DecryptionShareProof struct {
	A ECPoint `json:"a"`
	B ECPoint `json:"b"`
	Z string  `json:"z"` // 32-byte hex scalar
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

type TrusteeShareFile struct {
	AuthorityID int     `json:"authorityId"`
	Name        string  `json:"name"`
	SecretShare string  `json:"secretShare"` // Hex scalar s_i
	PubKeyShare ECPoint `json:"pubKeyShare"`  // Y_i = s_i * G
	GlobalPub   ECPoint `json:"globalPubKey"` // Y = x * G
	Threshold   int     `json:"threshold"`
	TotalEAs    int     `json:"totalEAs"`
}
