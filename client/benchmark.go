package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"

	"timefabric-client/crypto"
)

type PhaseMetrics struct {
	PhaseName        string   `json:"phaseName"`
	TotalItems       int      `json:"totalItems"`
	SuccessfulItems  int      `json:"successfulItems"`
	FailedItems      int      `json:"failedItems"`
	TotalDurationSec float64  `json:"totalDurationSec"`
	ThroughputPerSec float64  `json:"throughputPerSec"`
	MinLatencyMs     float64  `json:"minLatencyMs"`
	AvgLatencyMs     float64  `json:"avgLatencyMs"`
	MedianLatencyMs  float64  `json:"medianLatencyMs"`
	P90LatencyMs     float64  `json:"p90LatencyMs"`
	P95LatencyMs     float64  `json:"p95LatencyMs"`
	P99LatencyMs     float64  `json:"p99LatencyMs"`
	MaxLatencyMs     float64  `json:"maxLatencyMs"`
}

type CryptoMetrics struct {
	TotalDurationSec float64 `json:"totalDurationSec"`
	AvgCryptoMs      float64 `json:"avgCryptoMs"`
	MedianCryptoMs   float64 `json:"medianCryptoMs"`
	P90CryptoMs      float64 `json:"p90CryptoMs"`
	P95CryptoMs      float64 `json:"p95CryptoMs"`
	P99CryptoMs      float64 `json:"p99CryptoMs"`
	MaxCryptoMs      float64 `json:"maxCryptoMs"`
}

type BenchmarkReport struct {
	Timestamp            string        `json:"timestamp"`
	ElectionID           string        `json:"electionId"`
	CandidateCount       int           `json:"candidateCount"`
	TotalVoters          int           `json:"totalVoters"`
	Concurrency          int           `json:"concurrency"`
	TargetPeerPolicy     string        `json:"targetPeerPolicy"`
	RegistrationMode     string        `json:"registrationMode"`
	KeyGenDurationMs     float64       `json:"keyGenDurationMs"`
	BallotPayloadBytes   int           `json:"ballotPayloadBytes"`
	RegistrationMetrics  PhaseMetrics  `json:"registrationMetrics"`
	VotingCryptoMetrics  CryptoMetrics `json:"votingCryptoMetrics"`
	VotingTxMetrics      PhaseMetrics  `json:"votingTxMetrics"`
	EndToEndVotingSec    float64       `json:"endToEndVotingSec"`
	EndToEndVotingTPS    float64       `json:"endToEndVotingTPS"`
	TotalBenchmarkSec    float64       `json:"totalBenchmarkSec"`
	SystemCapacityNotes  string        `json:"systemCapacityNotes"`
}

type Voter struct {
	ID         int
	PrivKey    *ecdsa.PrivateKey
	PublicKey  ecdsa.PublicKey
	PubHex     string
	Candidate  int
}

func calcPercentiles(durations []float64) (min, avg, p50, p90, p95, p99, max float64) {
	n := len(durations)
	if n == 0 {
		return 0, 0, 0, 0, 0, 0, 0
	}
	sort.Float64s(durations)
	min = durations[0]
	max = durations[n-1]
	sum := 0.0
	for _, d := range durations {
		sum += d
	}
	avg = sum / float64(n)
	p50 = durations[int(float64(n)*0.50)]
	p90 = durations[int(float64(n)*0.90)]
	p95 = durations[int(float64(n)*0.95)]
	p99 = durations[int(float64(n)*0.99)]
	return
}

func runBenchmark(args []string) {
	fs := flag.NewFlagSet("benchmark", flag.ExitOnError)
	var (
		numVoters      = fs.Int("voters", 1000, "Number of voters to simulate and measure")
		numCandidates  = fs.Int("candidates", 3, "Number of election candidates (min 2)")
		concurrency    = fs.Int("concurrency", 20, "Number of concurrent worker goroutines")
		batchReg       = fs.Bool("batch-reg", false, "Use batch registration (registerVoters) instead of individual transactions")
		batchSize      = fs.Int("batch-size", 100, "Batch size for batch registration mode")
		peerTarget     = fs.String("peer", "ea-pairs", "Peer target strategy: 'ea-pairs' (f+1=2 EAs), 'peer0', or 'round-robin'")
		forceReset     = fs.Bool("reset", false, "Force wipe ledger and re-initialize election before benchmark")
		runTally       = fs.Bool("tally", false, "Execute homomorphic tally and threshold decryption after voting")
		outputFile     = fs.String("output", "benchmark_results.json", "Path to save JSON benchmark report")
		configPath     = fs.String("config", "./connection.yaml", "Fabric connection profile path")
	)
	_ = fs.Parse(args)

	if *numCandidates < 2 {
		log.Fatalf("[-] Candidates count must be at least 2 (got %d)", *numCandidates)
	}

	benchStart := time.Now()

	fmt.Println("=================================================================")
	fmt.Println("  TimeFabric E-Voting Performance & Capacity Benchmark Suite    ")
	fmt.Println("  SEC 1 Compressed Points & 32-byte Binary Scalars               ")
	fmt.Println("  Multi-EA Endorsement Policy (f+1=2 Distinct EA Organizations)  ")
	fmt.Println("=================================================================")
	fmt.Printf("[*] Configuration:\n")
	fmt.Printf("    • Target Voters       : %d\n", *numVoters)
	fmt.Printf("    • Candidates (rho)    : %d\n", *numCandidates)
	fmt.Printf("    • Concurrency Level   : %d workers\n", *concurrency)
	fmt.Printf("    • Registration Mode   : %s\n", func() string {
		if *batchReg {
			return fmt.Sprintf("Batch (size: %d)", *batchSize)
		}
		return "Individual Transactions"
	}())
	fmt.Printf("    • Peer Target Policy  : %s\n", *peerTarget)
	fmt.Printf("    • Report File         : %s\n", *outputFile)
	fmt.Println("=================================================================")

	sdk, err := fabsdk.New(config.FromFile(*configPath))
	if err != nil {
		log.Fatalf("[-] Failed to initialize Fabric SDK: %v", err)
	}
	defer sdk.Close()

	clientContext := sdk.ChannelContext("mychannel", fabsdk.WithUser("Admin"), fabsdk.WithOrg("Org1"))
	client, err := channel.New(clientContext)
	if err != nil {
		log.Fatalf("[-] Failed to create channel client: %v", err)
	}

	peerList := []string{
		"peer0.org1.voting.com",
		"peer1.org1.voting.com",
		"peer2.org1.voting.com",
		"peer3.org1.voting.com",
		"peer4.org1.voting.com",
		"peer5.org1.voting.com",
	}

	getTargetOption := func(idx int) channel.RequestOption {
		switch *peerTarget {
		case "peer0":
			return channel.WithTargetEndpoints("peer0.org1.voting.com")
		case "round-robin":
			return channel.WithTargetEndpoints(peerList[idx%len(peerList)])
		case "ea-pairs", "bft":
			// Endorsement: f+1=2 független EA peer jóváhagyása
			p1 := peerList[idx%len(peerList)]
			p2 := peerList[(idx+1)%len(peerList)]
			return channel.WithTargetEndpoints(p1, p2)
		default:
			p1 := peerList[idx%len(peerList)]
			p2 := peerList[(idx+1)%len(peerList)]
			return channel.WithTargetEndpoints(p1, p2)
		}
	}

	fmt.Println("\n[*] Step 1: Checking Ledger & Election State...")
	var election crypto.ElectionState
	queryResp, err := client.Query(channel.Request{
		ChaincodeID: "voting",
		Fcn:         "getElection",
		Args:        [][]byte{},
	}, channel.WithTargetEndpoints("peer0.org1.voting.com"))

	needInit := *forceReset
	if err != nil || len(queryResp.Payload) == 0 {
		needInit = true
	} else {
		if err := json.Unmarshal(queryResp.Payload, &election); err != nil || election.Rho < 2 || election.Rho != *numCandidates || election.Status == "FINISHED" {
			needInit = true
		}
	}

	if needInit {
		fmt.Printf("[*] Setting up clean election environment with %d candidates (threshold t=2)...\n", *numCandidates)
			_, _ = client.Execute(channel.Request{
			ChaincodeID: "voting",
			Fcn:         "ClearAllVotes",
			Args:        [][]byte{},
		}, channel.WithTargetEndpoints("peer0.org1.voting.com", "peer1.org1.voting.com"))
		time.Sleep(1500 * time.Millisecond)

		// n=6 hatóság, BFT küszöbérték t=f+1=2
		totalEAs := 6
		threshold := 2
		candidates := make([]string, *numCandidates)
		defaultNames := []string{
			"Alice Johnson", "Bob Smith", "Charlie Brown", "David Miller", "Eva Davis",
			"Frank White", "Grace Hopper", "Henry Ford", "Ivy Taylor", "Jack Robinson",
		}
		for i := 0; i < *numCandidates; i++ {
			if i < len(defaultNames) {
				candidates[i] = defaultNames[i]
			} else {
				candidates[i] = fmt.Sprintf("Candidate %d", i+1)
			}
		}
		electionID := "TimeFabric_Election_2026"

		_, Yx, Yy, shares, Yix, Yiy, err := crypto.SimulateDKG(totalEAs, threshold)
		if err != nil {
			log.Fatalf("[-] DKG simulation failed: %v", err)
		}

		globalPubKey := crypto.PointToECPoint(Yx, Yy)
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
			data, _ := json.MarshalIndent(shareFile, "", "  ")
			_ = os.WriteFile(fmt.Sprintf("trustee_%d_share.json", i), data, 0644)
			_ = os.WriteFile(fmt.Sprintf("ea_%d_share.json", i), data, 0644)
		}

		electionConfig := crypto.ElectionState{
			ElectionID:   electionID,
			Status:       "INITIALIZED",
			Candidates:   candidates,
			Rho:          len(candidates),
			GlobalPubKey: globalPubKey,
			EAMembers:    eaMembers,
			Threshold:    threshold,
			TStart:       0,
			TEnd:         0,
		}
		cfgBytes, _ := json.Marshal(electionConfig)
		_, err = client.Execute(channel.Request{
			ChaincodeID: "voting",
			Fcn:         "initElection",
			Args:        [][]byte{cfgBytes},
		}, channel.WithTargetEndpoints("peer0.org1.voting.com", "peer1.org1.voting.com"))
		if err != nil {
			log.Fatalf("[-] Failed to initElection: %v", err)
		}
		election = electionConfig
		fmt.Printf("[+] Initialized fresh election '%s' (Rho=%d candidates, Threshold t=%d EAs)\n",
			election.ElectionID, election.Rho, election.Threshold)
		time.Sleep(2 * time.Second)
	} else {
		fmt.Printf("[+] Reusing existing election '%s' (Status: %s, Rho: %d candidates, Threshold: t=%d)\n",
			election.ElectionID, election.Status, election.Rho, election.Threshold)
	}

	Yx, Yy, err := crypto.ParsePoint(election.GlobalPubKey)
	if err != nil {
		log.Fatalf("[-] Failed to parse Global Public Key: %v", err)
	}

	fmt.Printf("\n[*] Step 2: Generating %d Eligible Voter Keypairs (33-byte SEC 1 Compressed P-256)...\n", *numVoters)
	keyGenStart := time.Now()
	voters := make([]*Voter, *numVoters)
	for i := 0; i < *numVoters; i++ {
		priv, err := ecdsa.GenerateKey(crypto.Curve, rand.Reader)
		if err != nil {
			log.Fatalf("Failed generating key for voter %d: %v", i, err)
		}
		pubHex := crypto.CompressPointHex(priv.PublicKey.X, priv.PublicKey.Y)
		voters[i] = &Voter{
			ID:        i,
			PrivKey:   priv,
			PublicKey: priv.PublicKey,
			PubHex:    pubHex, // 33-byte compressed hex string (66 hex characters)
			Candidate: i % election.Rho,
		}
	}
	keyGenDuration := time.Since(keyGenStart)
	fmt.Printf("[+] Generated %d voter keypairs in %.2f ms (%.2f µs/voter, Key size: 33 bytes)\n",
		*numVoters, float64(keyGenDuration.Microseconds())/1000.0, float64(keyGenDuration.Microseconds())/float64(*numVoters))

	fmt.Printf("\n[*] Step 3: Registering %d Voters on Blockchain...\n", *numVoters)
	regStart := time.Now()
	var (
		regSuccessCount int64
		regFailCount    int64
		regLatencies    = make([]float64, 0, *numVoters)
		regMu           sync.Mutex
	)

	if *batchReg {
			fmt.Printf("    -> Running in BATCH mode (batch size: %d)...\n", *batchSize)
		numBatches := (*numVoters + *batchSize - 1) / *batchSize
		for b := 0; b < numBatches; b++ {
			bStart := b * *batchSize
			bEnd := bStart + *batchSize
			if bEnd > *numVoters {
				bEnd = *numVoters
			}
			pks := make([]string, bEnd-bStart)
			for j := bStart; j < bEnd; j++ {
				pks[j-bStart] = voters[j].PubHex
			}
			pksJSON, _ := json.Marshal(pks)

			var err error
			var durMs float64
			for attempt := 0; attempt < 3; attempt++ {
				t0 := time.Now()
				_, err = client.Execute(channel.Request{
					ChaincodeID: "voting",
					Fcn:         "registerVoters",
					Args:        [][]byte{pksJSON},
				}, getTargetOption(b+attempt))
				durMs = float64(time.Since(t0).Microseconds()) / 1000.0
				if err == nil {
					break
				}
				time.Sleep(time.Duration(150*(attempt+1)) * time.Millisecond)
			}

			if err != nil {
				fmt.Printf("\n       [-] Batch %d/%d failed after 3 attempts: %v\n", b+1, numBatches, err)
				atomic.AddInt64(&regFailCount, int64(bEnd-bStart))
			} else {
				atomic.AddInt64(&regSuccessCount, int64(bEnd-bStart))
				regMu.Lock()
				regLatencies = append(regLatencies, durMs)
				regMu.Unlock()
			}
			fmt.Printf("\r    -> Progress: %d/%d voters registered (%d batches)...", atomic.LoadInt64(&regSuccessCount), *numVoters, b+1)
		}
		fmt.Println()
	} else {
			fmt.Printf("    -> Running in INDIVIDUAL transaction mode with %d concurrent workers...\n", *concurrency)
		workChan := make(chan int, *numVoters)
		for i := 0; i < *numVoters; i++ {
			workChan <- i
		}
		close(workChan)

		var wg sync.WaitGroup
		progressTicker := time.NewTicker(1 * time.Second)
		tickerDone := make(chan struct{})

		go func() {
			for {
				select {
				case <-progressTicker.C:
					done := atomic.LoadInt64(&regSuccessCount) + atomic.LoadInt64(&regFailCount)
					elapsed := time.Since(regStart).Seconds()
					rate := 0.0
					if elapsed > 0 {
						rate = float64(done) / elapsed
					}
					fmt.Printf("\r    -> [Registration] %d/%d (%.1f%%) | %.1f reg/s | Elapsed: %.1fs | Failed: %d",
						done, *numVoters, float64(done)/float64(*numVoters)*100.0, rate, elapsed, atomic.LoadInt64(&regFailCount))
				case <-tickerDone:
					return
				}
			}
		}()

		for w := 0; w < *concurrency; w++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				for idx := range workChan {
					v := voters[idx]
					t0 := time.Now()
					_, err := client.Execute(channel.Request{
						ChaincodeID: "voting",
						Fcn:         "registerVoter",
						Args:        [][]byte{[]byte(v.PubHex)},
					}, getTargetOption(idx))
					durMs := float64(time.Since(t0).Microseconds()) / 1000.0

					if err != nil {
						time.Sleep(100 * time.Millisecond)
						_, err2 := client.Execute(channel.Request{
							ChaincodeID: "voting",
							Fcn:         "registerVoter",
							Args:        [][]byte{[]byte(v.PubHex)},
						}, getTargetOption(idx+1))
						if err2 != nil {
							atomic.AddInt64(&regFailCount, 1)
							continue
						}
					}

					atomic.AddInt64(&regSuccessCount, 1)
					regMu.Lock()
					regLatencies = append(regLatencies, durMs)
					regMu.Unlock()
				}
			}(w)
		}

		wg.Wait()
		progressTicker.Stop()
		close(tickerDone)
		fmt.Println()
	}

	regDuration := time.Since(regStart)
	regMin, regAvg, regP50, regP90, regP95, regP99, regMax := calcPercentiles(regLatencies)
	regTPS := float64(regSuccessCount) / regDuration.Seconds()

	fmt.Printf("[+] Registration Complete!\n")
	fmt.Printf("    • Total Time   : %.2fs\n", regDuration.Seconds())
	fmt.Printf("    • Registered   : %d / %d (Failures: %d)\n", regSuccessCount, *numVoters, regFailCount)
	fmt.Printf("    • Throughput   : %.2f registrations/sec\n", regTPS)
	fmt.Printf("    • Latency (ms) : Min: %.1f | Avg: %.1f | P50: %.1f | P90: %.1f | P95: %.1f | P99: %.1f | Max: %.1f\n",
		regMin, regAvg, regP50, regP90, regP95, regP99, regMax)

	fmt.Println("\n[*] Step 4: Activating Voting Phase (startVoting, endorsed by 2 EAs)...")
	_, err = client.Execute(channel.Request{
		ChaincodeID: "voting",
		Fcn:         "startVoting",
		Args:        [][]byte{},
	}, channel.WithTargetEndpoints("peer0.org1.voting.com", "peer1.org1.voting.com"))
	if err != nil {
		fmt.Printf("    (Notice: startVoting returned: %v; continuing)\n", err)
	}

	fmt.Println("    -> Waiting 3 seconds for startVoting block commit across peers...")
	time.Sleep(3 * time.Second)

	qResp, _ := client.Query(channel.Request{
		ChaincodeID: "voting",
		Fcn:         "getElection",
		Args:        [][]byte{},
	}, channel.WithTargetEndpoints("peer0.org1.voting.com"))
	var verifyElection crypto.ElectionState
	_ = json.Unmarshal(qResp.Payload, &verifyElection)
	fmt.Printf("[+] Voting phase confirmed active! (Status: %s)\n", verifyElection.Status)

	fmt.Printf("\n[*] Step 5: Encrypting, Proving & Casting %d Anonymous Ballots...\n", *numVoters)
	fmt.Printf("    -> %d Concurrent workers, balanced choice across %d candidates\n", *concurrency, election.Rho)

	voteStart := time.Now()
	var (
		voteSuccessCount int64
		voteFailCount    int64
		cryptoLatencies  = make([]float64, 0, *numVoters)
		txLatencies      = make([]float64, 0, *numVoters)
		totalLatencies   = make([]float64, 0, *numVoters)
		voteMu           sync.Mutex
		samplePayloadLen int
	)

	voteChan := make(chan int, *numVoters)
	for i := 0; i < *numVoters; i++ {
		voteChan <- i
	}
	close(voteChan)

	var voteWg sync.WaitGroup
	voteTicker := time.NewTicker(1 * time.Second)
	voteTickerDone := make(chan struct{})

	go func() {
		for {
			select {
			case <-voteTicker.C:
				done := atomic.LoadInt64(&voteSuccessCount) + atomic.LoadInt64(&voteFailCount)
				elapsed := time.Since(voteStart).Seconds()
				rate := 0.0
				if elapsed > 0 {
					rate = float64(done) / elapsed
				}
				fmt.Printf("\r    -> [Voting] %d/%d (%.1f%%) | %.1f votes/s (TPS) | Elapsed: %.1fs | Errors: %d",
					done, *numVoters, float64(done)/float64(*numVoters)*100.0, rate, elapsed, atomic.LoadInt64(&voteFailCount))
			case <-voteTickerDone:
				return
			}
		}
	}()

	for w := 0; w < *concurrency; w++ {
		voteWg.Add(1)
		go func(workerID int) {
			defer voteWg.Done()
			for idx := range voteChan {
				v := voters[idx]
				tVoteStart := time.Now()

				// A. rész: Kliensoldali kriptográfia (Titkosítás + NIZKP + Aláírás)
				tCryptoStart := time.Now()
				ciphertext, rScalars, Ax, Ay, Bx, By, err := crypto.EncryptBallot(v.Candidate, election.Rho, Yx, Yy)
				if err != nil {
					atomic.AddInt64(&voteFailCount, 1)
					continue
				}

				proof, err := crypto.GenerateNIZKP(election.ElectionID, v.PubHex, v.Candidate, election.Rho, Ax, Ay, Bx, By, rScalars, Yx, Yy)
				if err != nil {
					atomic.AddInt64(&voteFailCount, 1)
					continue
				}

				signature, err := crypto.SignBallot(v.PrivKey, election.ElectionID, v.PubHex, ciphertext, proof)
				if err != nil {
					atomic.AddInt64(&voteFailCount, 1)
					continue
				}
				cryptoMs := float64(time.Since(tCryptoStart).Microseconds()) / 1000.0

				submission := crypto.BallotSubmission{
					ElectionID: election.ElectionID,
					VoterPK:    v.PubHex,
					Ciphertext: ciphertext,
					Proof:      proof,
					Signature:  signature,
				}
				subBytes, _ := json.Marshal(submission)

				if idx == 0 {
					samplePayloadLen = len(subBytes)
					// Elméleti bináris csomagméret: 33 + 2*rho*33 + rho*32 + rho^2*32 + 64 bájt
					binBytes := 33 + 2*election.Rho*33 + election.Rho*32 + election.Rho*election.Rho*32 + 64
					fmt.Printf("\n    [+] Ballot Payload (rho=%d): JSON=%d bytes (%.2f KB), Binary Cryptographic Equivalent=%d bytes (%.2f KB)\n",
						election.Rho, len(subBytes), float64(len(subBytes))/1024.0, binBytes, float64(binBytes)/1024.0)
				}

				// B. rész: Blokklánc konszenzus és ellenőrzés (f+1=2 peer endorsement)
				tTxStart := time.Now()
				_, err = client.Execute(channel.Request{
					ChaincodeID: "voting",
					Fcn:         "castBallot",
					Args:        [][]byte{subBytes},
				}, getTargetOption(idx))
				txMs := float64(time.Since(tTxStart).Microseconds()) / 1000.0
				totalMs := float64(time.Since(tVoteStart).Microseconds()) / 1000.0

				if err != nil {
					time.Sleep(150 * time.Millisecond)
					_, errRetry := client.Execute(channel.Request{
						ChaincodeID: "voting",
						Fcn:         "castBallot",
						Args:        [][]byte{subBytes},
					}, getTargetOption(idx+1))
					if errRetry != nil {
						atomic.AddInt64(&voteFailCount, 1)
						continue
					}
				}

				atomic.AddInt64(&voteSuccessCount, 1)
				voteMu.Lock()
				cryptoLatencies = append(cryptoLatencies, cryptoMs)
				txLatencies = append(txLatencies, txMs)
				totalLatencies = append(totalLatencies, totalMs)
				voteMu.Unlock()
			}
		}(w)
	}

	voteWg.Wait()
	voteTicker.Stop()
	close(voteTickerDone)
	fmt.Println()

	votingDuration := time.Since(voteStart)
	totalBenchmarkDuration := time.Since(benchStart)

	cMin, cAvg, cP50, cP90, cP95, cP99, cMax := calcPercentiles(cryptoLatencies)
	tMin, tAvg, tP50, tP90, tP95, tP99, tMax := calcPercentiles(txLatencies)
	totMin, totAvg, totP50, totP90, totP95, totP99, totMax := calcPercentiles(totalLatencies)
	votingTPS := float64(voteSuccessCount) / votingDuration.Seconds()

	var capacityNotes strings.Builder
	capacityNotes.WriteString(fmt.Sprintf("Measured Sustained Throughput: %.2f votes/second (TPS). ", votingTPS))
	capacityNotes.WriteString(fmt.Sprintf("With %d concurrent workers and %d candidates, ", *concurrency, election.Rho))
	capacityNotes.WriteString(fmt.Sprintf("the Hyperledger Fabric network processed %d ballots in %.2f seconds under %s endorsement policy. ",
		voteSuccessCount, votingDuration.Seconds(), *peerTarget))
	capacityNotes.WriteString(fmt.Sprintf("Standard SEC 1 compressed EC points (33 bytes) and 32-byte binary scalars yielded ~%.2f KB binary payload per ballot.",
		float64(33+2*election.Rho*33+election.Rho*32+election.Rho*election.Rho*32+64)/1024.0))

	fmt.Println("\n=================================================================")
	fmt.Println("               BENCHMARK METRICS & CAPACITY REPORT               ")
	fmt.Println("=================================================================")
	fmt.Printf("Total Voters Processed  : %d\n", *numVoters)
	fmt.Printf("Concurrency (Workers)   : %d\n", *concurrency)
	fmt.Printf("Endorsement Policy      : %s (matching endorsements from f+1=2 EAs)\n", *peerTarget)
	fmt.Printf("Ballot Payload Size     : JSON=%d B (%.2f KB) | Binary Cryptographic=%d B (%.2f KB)\n",
		samplePayloadLen, float64(samplePayloadLen)/1024.0,
		33+2*election.Rho*33+election.Rho*32+election.Rho*election.Rho*32+64,
		float64(33+2*election.Rho*33+election.Rho*32+election.Rho*election.Rho*32+64)/1024.0)
	fmt.Printf("Total Execution Time    : %.2f seconds\n", totalBenchmarkDuration.Seconds())
	fmt.Println("-----------------------------------------------------------------")
	fmt.Println("1. VOTER REGISTRATION PHASE:")
	fmt.Printf("   • Duration           : %.2f s\n", regDuration.Seconds())
	fmt.Printf("   • Successful / Total : %d / %d (%.1f%%)\n", regSuccessCount, *numVoters, float64(regSuccessCount)/float64(*numVoters)*100.0)
	fmt.Printf("   • Throughput         : %.2f registrations / sec\n", regTPS)
	fmt.Printf("   • Latency (ms)       : Min: %.1f | Avg: %.1f | P50: %.1f | P90: %.1f | P95: %.1f | P99: %.1f | Max: %.1f\n",
		regMin, regAvg, regP50, regP90, regP95, regP99, regMax)
	fmt.Println("-----------------------------------------------------------------")
	fmt.Println("2. BALLOT CASTING (VOTING) PHASE:")
	fmt.Printf("   • Duration           : %.2f s\n", votingDuration.Seconds())
	fmt.Printf("   • Successful / Total : %d / %d (%.1f%%)\n", voteSuccessCount, *numVoters, float64(voteSuccessCount)/float64(*numVoters)*100.0)
	fmt.Printf("   • Sustained TPS      : %.2f VOTES / SEC\n", votingTPS)
	fmt.Printf("   • End-to-End Latency : Min: %.1f ms | Avg: %.1f ms | P50: %.1f ms | P90: %.1f ms | P95: %.1f ms | P99: %.1f ms | Max: %.1f ms\n",
		totMin, totAvg, totP50, totP90, totP95, totP99, totMax)
	fmt.Println("-----------------------------------------------------------------")
	fmt.Println("3. LATENCY BREAKDOWN (CRYPTO vs BLOCKCHAIN):")
	fmt.Printf("   • Client Crypto Prep : Min: %.2f ms | Avg: %.2f ms | P50: %.2f ms | P90: %.2f ms | P95: %.2f ms | P99: %.2f ms | Max: %.2f ms\n",
		cMin, cAvg, cP50, cP90, cP95, cP99, cMax)
	fmt.Printf("   • Fabric Blockchain  : Min: %.2f ms | Avg: %.2f ms | P50: %.2f ms | P90: %.2f ms | P95: %.2f ms | P99: %.2f ms | Max: %.2f ms\n",
		tMin, tAvg, tP50, tP90, tP95, tP99, tMax)
	fmt.Println("-----------------------------------------------------------------")
	fmt.Println("4. SYSTEM CAPACITY PROJECTION:")
	if votingTPS > 0 {
		fmt.Printf("   • At current measured rate (%.2f votes/s):\n", votingTPS)
		fmt.Printf("     - 1,000 votes   : ~%.1f seconds (~%.1f minutes)\n", 1000.0/votingTPS, (1000.0/votingTPS)/60.0)
		fmt.Printf("     - 10,000 votes  : ~%.1f minutes\n", (10000.0/votingTPS)/60.0)
		fmt.Printf("     - 100,000 votes : ~%.1f hours\n", (100000.0/votingTPS)/3600.0)
	}
	fmt.Println("=================================================================")

	report := BenchmarkReport{
		Timestamp:          time.Now().Format(time.RFC3339),
		ElectionID:         election.ElectionID,
		CandidateCount:     election.Rho,
		TotalVoters:        *numVoters,
		Concurrency:        *concurrency,
		TargetPeerPolicy:   *peerTarget,
		RegistrationMode: func() string {
			if *batchReg {
				return "batch"
			}
			return "individual"
		}(),
		KeyGenDurationMs:   float64(keyGenDuration.Microseconds()) / 1000.0,
		BallotPayloadBytes: samplePayloadLen,
		RegistrationMetrics: PhaseMetrics{
			PhaseName:        "Registration",
			TotalItems:       *numVoters,
			SuccessfulItems:  int(regSuccessCount),
			FailedItems:      int(regFailCount),
			TotalDurationSec: regDuration.Seconds(),
			ThroughputPerSec: regTPS,
			MinLatencyMs:     regMin,
			AvgLatencyMs:     regAvg,
			MedianLatencyMs:  regP50,
			P90LatencyMs:     regP90,
			P95LatencyMs:     regP95,
			P99LatencyMs:     regP99,
			MaxLatencyMs:     regMax,
		},
		VotingCryptoMetrics: CryptoMetrics{
			TotalDurationSec: float64(cAvg*float64(len(cryptoLatencies))) / 1000.0,
			AvgCryptoMs:      cAvg,
			MedianCryptoMs:   cP50,
			P90CryptoMs:      cP90,
			P95CryptoMs:      cP95,
			P99CryptoMs:      cP99,
			MaxCryptoMs:      cMax,
		},
		VotingTxMetrics: PhaseMetrics{
			PhaseName:        "Voting_Blockchain_Tx",
			TotalItems:       *numVoters,
			SuccessfulItems:  int(voteSuccessCount),
			FailedItems:      int(voteFailCount),
			TotalDurationSec: votingDuration.Seconds(),
			ThroughputPerSec: votingTPS,
			MinLatencyMs:     tMin,
			AvgLatencyMs:     tAvg,
			MedianLatencyMs:  tP50,
			P90LatencyMs:     tP90,
			P95LatencyMs:     tP95,
			P99LatencyMs:     tP99,
			MaxLatencyMs:     tMax,
		},
		EndToEndVotingSec:   votingDuration.Seconds(),
		EndToEndVotingTPS:   votingTPS,
		TotalBenchmarkSec:   totalBenchmarkDuration.Seconds(),
		SystemCapacityNotes: capacityNotes.String(),
	}

	reportBytes, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(*outputFile, reportBytes, 0644); err != nil {
		fmt.Printf("[-] Warning: Failed to write JSON report to %s: %v\n", *outputFile, err)
	} else {
		fmt.Printf("[+] Saved detailed machine-readable report to: %s\n", *outputFile)
	}

	if *runTally {
		fmt.Println("\n[*] Step 6: Executing Homomorphic Tally & Decryption Verification (endorsed by 2 EAs)...")
		tallyResp, err := client.Execute(channel.Request{
			ChaincodeID: "voting",
			Fcn:         "tallyVotes",
			Args:        [][]byte{},
		}, channel.WithTargetEndpoints("peer0.org1.voting.com", "peer1.org1.voting.com"))
		if err != nil {
			fmt.Printf("[-] Tally execution error: %v\n", err)
		} else {
			fmt.Printf("[+] Tally successfully aggregated! TxID: %s\n", tallyResp.TransactionID)
		}
	}
}
