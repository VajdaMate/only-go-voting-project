package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

var (
	Curve = elliptic.P256()
	Q     = Curve.Params().N
	P     = Curve.Params().P
	Gx    = Curve.Params().Gx
	Gy    = Curve.Params().Gy
	expP4 = new(big.Int).Rsh(new(big.Int).Add(P, big.NewInt(1)), 2) // (P + 1) / 4
)

func CompressPoint(x, y *big.Int) []byte {
	if x == nil || y == nil || (x.Sign() == 0 && y.Sign() == 0) {
		return []byte{0x00}
	}
	b := make([]byte, 33)
	if y.Bit(0) == 0 {
		b[0] = 0x02
	} else {
		b[0] = 0x03
	}
	xb := x.Bytes()
	copy(b[33-len(xb):], xb)
	return b
}

func CompressPointHex(x, y *big.Int) string {
	return hex.EncodeToString(CompressPoint(x, y))
}

func DecompressPoint(data []byte) (*big.Int, *big.Int, error) {
	if len(data) == 1 && data[0] == 0x00 {
		return big.NewInt(0), big.NewInt(0), nil
	}
	if len(data) == 65 && data[0] == 0x04 {
		x, y := elliptic.Unmarshal(Curve, data)
		if x == nil || y == nil {
			return nil, nil, fmt.Errorf("invalid uncompressed point")
		}
		return x, y, nil
	}
	if len(data) != 33 {
		return nil, nil, fmt.Errorf("invalid compressed point length: %d (expected 33 bytes)", len(data))
	}
	if data[0] != 0x02 && data[0] != 0x03 {
		return nil, nil, fmt.Errorf("invalid compressed point prefix: %02x (expected 02 or 03)", data[0])
	}
	x := new(big.Int).SetBytes(data[1:])
	// y^2 = x^3 - 3x + b mod p
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	threeX := new(big.Int).Mul(big.NewInt(3), x)
	y2 := new(big.Int).Sub(x3, threeX)
	y2.Add(y2, Curve.Params().B)
	y2.Mod(y2, P)

	y := new(big.Int).Exp(y2, expP4, P)
	expectedParity := uint(data[0] & 1)
	if y.Bit(0) != expectedParity {
		y.Sub(P, y)
	}

	if !Curve.IsOnCurve(x, y) {
		return nil, nil, fmt.Errorf("decompressed point is not on curve P-256")
	}
	return x, y, nil
}

func DecompressPointHex(s string) (*big.Int, *big.Int, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if s == "" || s == "00" || s == "0" {
		return big.NewInt(0), big.NewInt(0), nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid hex point: %v", err)
	}
	return DecompressPoint(b)
}

func ParseBigInt(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty integer string")
	}
	bi := new(big.Int)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		_, ok := bi.SetString(s[2:], 16)
		if !ok {
			return nil, fmt.Errorf("invalid hex integer: %s", s)
		}
		return bi, nil
	}
	_, ok := bi.SetString(s, 10)
	if ok {
		return bi, nil
	}
	_, ok = bi.SetString(s, 16)
	if ok {
		return bi, nil
	}
	return nil, fmt.Errorf("invalid integer: %s", s)
}

func IsPointAtInfinity(x, y *big.Int) bool {
	return x == nil || y == nil || (x.Sign() == 0 && y.Sign() == 0)
}

func PointNeg(x, y *big.Int) (*big.Int, *big.Int) {
	if IsPointAtInfinity(x, y) {
		return big.NewInt(0), big.NewInt(0)
	}
	negY := new(big.Int).Sub(P, y)
	negY.Mod(negY, P)
	return new(big.Int).Set(x), negY
}

func PointSub(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if IsPointAtInfinity(x2, y2) {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}
	nx, ny := PointNeg(x2, y2)
	if IsPointAtInfinity(x1, y1) {
		return nx, ny
	}
	return Curve.Add(x1, y1, nx, ny)
}

func ParsePoint(p ECPoint) (*big.Int, *big.Int, error) {
	cleanX := strings.TrimPrefix(strings.TrimSpace(p.X), "0x")
	if len(cleanX) == 66 && (strings.HasPrefix(cleanX, "02") || strings.HasPrefix(cleanX, "03")) {
		return DecompressPointHex(cleanX)
	}

	x, err := ParseBigInt(p.X)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid point X: %v", err)
	}
	y, err := ParseBigInt(p.Y)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid point Y: %v", err)
	}
	if IsPointAtInfinity(x, y) {
		return big.NewInt(0), big.NewInt(0), nil
	}
	if !Curve.IsOnCurve(x, y) {
		return nil, nil, fmt.Errorf("point (%s, %s) is not on curve P-256", p.X, p.Y)
	}
	return x, y, nil
}

func PointToECPoint(x, y *big.Int) ECPoint {
	if IsPointAtInfinity(x, y) {
		return ECPoint{X: "0", Y: "0"}
	}
	return ECPoint{
		X: fmt.Sprintf("0x%x", x),
		Y: fmt.Sprintf("0x%x", y),
	}
}

func ComputeBallotHash(electionID, voterPK string, ciphertext BallotCiphertext, proof NIZKProof) string {
	h := sha256.New()
	h.Write([]byte(electionID))
	h.Write([]byte(voterPK))
	cBytes, _ := json.Marshal(ciphertext)
	h.Write(cBytes)
	pBytes, _ := json.Marshal(proof)
	h.Write(pBytes)
	return hex.EncodeToString(h.Sum(nil))
}

func EncryptBallot(candidateIndex, rho int, Yx, Yy *big.Int) (BallotCiphertext, []*big.Int, []*big.Int, []*big.Int, []*big.Int, []*big.Int, error) {
	if candidateIndex < 0 || candidateIndex >= rho {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("invalid candidate index: %d (rho=%d)", candidateIndex, rho)
	}

	cipher := make(BallotCiphertext, rho)
	rScalars := make([]*big.Int, rho)
	Ax := make([]*big.Int, rho)
	Ay := make([]*big.Int, rho)
	Bx := make([]*big.Int, rho)
	By := make([]*big.Int, rho)

	for i := 0; i < rho; i++ {
		r, err := rand.Int(rand.Reader, Q)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		rScalars[i] = r

		ax, ay := Curve.ScalarBaseMult(r.Bytes())
		Ax[i], Ay[i] = ax, ay

		rYx, rYy := Curve.ScalarMult(Yx, Yy, r.Bytes())
		if i == candidateIndex {
			// v_i = 1 -> B_i = 1*G + r_i*Y
			bx, by := Curve.Add(Gx, Gy, rYx, rYy)
			Bx[i], By[i] = bx, by
		} else {
			// v_i = 0 -> B_i = 0*G + r_i*Y = r_i*Y
			Bx[i], By[i] = rYx, rYy
		}

		cipher[i] = CiphertextComponent{
			A: PointToECPoint(Ax[i], Ay[i]),
			B: PointToECPoint(Bx[i], By[i]),
		}
	}

	return cipher, rScalars, Ax, Ay, Bx, By, nil
}

func GenerateNIZKP(electionID, voterPK string, chosenCandidate, rho int, Ax, Ay, Bx, By, rScalars []*big.Int, Yx, Yy *big.Int) (NIZKProof, error) {
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
		if k == chosenCandidate {
			continue
		}
		ck, err := rand.Int(rand.Reader, Q)
		if err != nil {
			return NIZKProof{}, err
		}
		c_k[k] = ck

		for i := 0; i < rho; i++ {
			zki, err := rand.Int(rand.Reader, Q)
			if err != nil {
				return NIZKProof{}, err
			}
			z_ki[k][i] = zki

			// Q_{k,i} = B_i - e_{k,i} * G
			var Qx, Qy *big.Int
			if k == i {
				Qx, Qy = PointSub(Bx[i], By[i], Gx, Gy)
			} else {
				Qx, Qy = Bx[i], By[i]
			}

			// U_{k,i} = z_{k,i} * G - c_k * A_i
			zGx, zGy := Curve.ScalarBaseMult(zki.Bytes())
			cAx, cAy := Curve.ScalarMult(Ax[i], Ay[i], ck.Bytes())
			U_x[k][i], U_y[k][i] = PointSub(zGx, zGy, cAx, cAy)

			// V_{k,i} = z_{k,i} * Y - c_k * Q_{k,i}
			zYx, zYy := Curve.ScalarMult(Yx, Yy, zki.Bytes())
			cQx, cQy := Curve.ScalarMult(Qx, Qy, ck.Bytes())
			V_x[k][i], V_y[k][i] = PointSub(zYx, zYy, cQx, cQy)
		}
	}

	// Valódi ág (k == chosen)
	omega := make([]*big.Int, rho)
	for i := 0; i < rho; i++ {
		w, err := rand.Int(rand.Reader, Q)
		if err != nil {
			return NIZKProof{}, err
		}
		omega[i] = w
		U_x[chosenCandidate][i], U_y[chosenCandidate][i] = Curve.ScalarBaseMult(w.Bytes())
		V_x[chosenCandidate][i], V_y[chosenCandidate][i] = Curve.ScalarMult(Yx, Yy, w.Bytes())
	}

	// Fiat-Shamir kihívás-hash
	h := sha256.New()
	h.Write([]byte(electionID))
	h.Write([]byte(voterPK))
	h.Write([]byte(fmt.Sprintf("%d", rho)))
	for i := 0; i < rho; i++ {
		h.Write(Ax[i].Bytes())
		h.Write(Ay[i].Bytes())
		h.Write(Bx[i].Bytes())
		h.Write(By[i].Bytes())
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
	cHash.Mod(cHash, Q)

	// c_chosen = c - sum c_k mod q
	cSumOther := big.NewInt(0)
	for k := 0; k < rho; k++ {
		if k != chosenCandidate {
			cSumOther.Add(cSumOther, c_k[k])
		}
	}
	cSumOther.Mod(cSumOther, Q)

	cChosen := new(big.Int).Sub(cHash, cSumOther)
	cChosen.Mod(cChosen, Q)
	if cChosen.Sign() < 0 {
		cChosen.Add(cChosen, Q)
	}
	c_k[chosenCandidate] = cChosen

	// z_chosen,i = omega_i + c_chosen * r_i mod q
	for i := 0; i < rho; i++ {
		cr := new(big.Int).Mul(cChosen, rScalars[i])
		cr.Mod(cr, Q)
		zi := new(big.Int).Add(omega[i], cr)
		zi.Mod(zi, Q)
		z_ki[chosenCandidate][i] = zi
	}

	proof := NIZKProof{
		Challenges: make([]string, rho),
		Responses:  make([][]string, rho),
	}
	for k := 0; k < rho; k++ {
		proof.Challenges[k] = fmt.Sprintf("%064x", c_k[k])
		proof.Responses[k] = make([]string, rho)
		for i := 0; i < rho; i++ {
			proof.Responses[k][i] = fmt.Sprintf("%064x", z_ki[k][i])
		}
	}

	return proof, nil
}

func SignBallot(voterPrivKey *ecdsa.PrivateKey, electionID, voterPK string, ciphertext BallotCiphertext, proof NIZKProof) (VoterSignature, error) {
	ballotHashStr := ComputeBallotHash(electionID, voterPK, ciphertext, proof)
	sigHashBytes, _ := hex.DecodeString(ballotHashStr)

	rSig, sSig, err := ecdsa.Sign(rand.Reader, voterPrivKey, sigHashBytes)
	if err != nil {
		return VoterSignature{}, err
	}

	return VoterSignature{
		R: fmt.Sprintf("%064x", rSig),
		S: fmt.Sprintf("%064x", sSig),
	}, nil
}

func SimulateDKG(n, threshold int) (*big.Int, *big.Int, *big.Int, []*big.Int, []*big.Int, []*big.Int, error) {
	if threshold < 1 || threshold > n {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("invalid threshold %d for %d participants", threshold, n)
	}

	// f(z) = a_0 + a_1*z + ... mod q
	coeffs := make([]*big.Int, threshold)
	for k := 0; k < threshold; k++ {
		c, err := rand.Int(rand.Reader, Q)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, err
		}
		coeffs[k] = c
	}

	xSecret := coeffs[0]
	Yx, Yy := Curve.ScalarBaseMult(xSecret.Bytes())

	shares := make([]*big.Int, n+1) // 1-indexed
	Yix := make([]*big.Int, n+1)
	Yiy := make([]*big.Int, n+1)

	for i := 1; i <= n; i++ {
		iz := big.NewInt(int64(i))
		si := big.NewInt(0)
		curZ := big.NewInt(1)

		for k := 0; k < threshold; k++ {
			term := new(big.Int).Mul(coeffs[k], curZ)
			term.Mod(term, Q)
			si.Add(si, term)
			si.Mod(si, Q)

			curZ.Mul(curZ, iz)
			curZ.Mod(curZ, Q)
		}

		shares[i] = si
		yx, yy := Curve.ScalarBaseMult(si.Bytes())
		Yix[i], Yiy[i] = yx, yy
	}

	return xSecret, Yx, Yy, shares, Yix, Yiy, nil
}

func GeneratePartialDecryption(electionID string, authorityID int, secretShare *big.Int, totals []CiphertextComponent, Y_i ECPoint) (AuthorityDecryptionSubmission, error) {
	rho := len(totals)
	shares := make([]CandidateDecryptionShare, rho)

	Y_i_x, Y_i_y, err := ParsePoint(Y_i)
	if err != nil {
		return AuthorityDecryptionSubmission{}, err
	}

	for j := 0; j < rho; j++ {
		C1x, C1y, err := ParsePoint(totals[j].A)
		if err != nil {
			return AuthorityDecryptionSubmission{}, err
		}

		// D_{i,j} = s_i * C_{1,j}^*
		Dij_x, Dij_y := Curve.ScalarMult(C1x, C1y, secretShare.Bytes())

		// DLEQ: log_G(Y_i) == log_C1(D_ij)
		r, err := rand.Int(rand.Reader, Q)
		if err != nil {
			return AuthorityDecryptionSubmission{}, err
		}

		Ax, Ay := Curve.ScalarBaseMult(r.Bytes())
		Bx, By := Curve.ScalarMult(C1x, C1y, r.Bytes())

		ph := sha256.New()
		ph.Write(Gx.Bytes())
		ph.Write(Gy.Bytes())
		ph.Write(C1x.Bytes())
		ph.Write(C1y.Bytes())
		ph.Write(Y_i_x.Bytes())
		ph.Write(Y_i_y.Bytes())
		ph.Write(Dij_x.Bytes())
		ph.Write(Dij_y.Bytes())
		ph.Write(Ax.Bytes())
		ph.Write(Ay.Bytes())
		ph.Write(Bx.Bytes())
		ph.Write(By.Bytes())

		cProof := new(big.Int).SetBytes(ph.Sum(nil))
		cProof.Mod(cProof, Q)

		cs := new(big.Int).Mul(cProof, secretShare)
		cs.Mod(cs, Q)
		zProof := new(big.Int).Add(r, cs)
		zProof.Mod(zProof, Q)

		shares[j] = CandidateDecryptionShare{
			CandidateIndex: j,
			D_ij:           PointToECPoint(Dij_x, Dij_y),
			Proof: DecryptionShareProof{
				A: PointToECPoint(Ax, Ay),
				B: PointToECPoint(Bx, By),
				Z: fmt.Sprintf("%064x", zProof),
			},
		}
	}

	return AuthorityDecryptionSubmission{
		ElectionID:  electionID,
		AuthorityID: authorityID,
		Shares:      shares,
	}, nil
}

func ComputeLagrangeCoefficients(S []int) (map[int]*big.Int, error) {
	lambdas := make(map[int]*big.Int)
	for _, i := range S {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for _, k := range S {
			if k == i {
				continue
			}
			num.Mul(num, big.NewInt(int64(k)))
			num.Mod(num, Q)

			diff := big.NewInt(int64(k - i))
			diff.Mod(diff, Q)
			if diff.Sign() < 0 {
				diff.Add(diff, Q)
			}
			den.Mul(den, diff)
			den.Mod(den, Q)
		}
		denInv := new(big.Int).ModInverse(den, Q)
		if denInv == nil {
			return nil, fmt.Errorf("modular inverse does not exist for Lagrange denominator")
		}
		lam := new(big.Int).Mul(num, denInv)
		lam.Mod(lam, Q)
		lambdas[i] = lam
	}
	return lambdas, nil
}

func SolveDiscreteLog(Mj_x, Mj_y *big.Int, maxVotes int64) (int64, error) {
	if IsPointAtInfinity(Mj_x, Mj_y) {
		return 0, nil
	}

	curX, curY := Gx, Gy
	for count := int64(1); count <= maxVotes; count++ {
		if curX.Cmp(Mj_x) == 0 && curY.Cmp(Mj_y) == 0 {
			return count, nil
		}
		curX, curY = Curve.Add(curX, curY, Gx, Gy)
	}

	return -1, fmt.Errorf("discrete log not found within range [0, %d]", maxVotes)
}
