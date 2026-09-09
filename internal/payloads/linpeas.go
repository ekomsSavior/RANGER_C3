package payloads

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func init() {
	Register(&LinPEAS{})
}

type LinPEAS struct{}

func (l *LinPEAS) Name() string     { return "linpeas_light" }
func (l *LinPEAS) Category() string { return "recon" }
func (l *LinPEAS) Description() string {
	return "Lightweight Linux PEAS scanner (sudo perms, SUID, cron, capabilities, kernel exploits)"
}

func (l *LinPEAS) Execute(args map[string]string) ([]byte, error) {
	results := l.execute()
	return MarshalJSON(results)
}

type peasResult struct {
	Timestamp    string         `json:"timestamp"`
	Hostname     string         `json:"hostname"`
	SudoChecks   []checkItem    `json:"sudo_checks"`
	SUIDBinaries []suidItem     `json:"suid_binaries"`
	Writable     []writableItem `json:"writable_files"`
	CronVulns    []checkItem    `json:"cron_vulns"`
	KernelExp    []checkItem    `json:"kernel_exploits"`
	Capabilities []capItem      `json:"capabilities"`
	Summary      map[string]int `json:"summary"`
}

type checkItem struct {
	Type        string `json:"type,omitempty"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Details     string `json:"details,omitempty"`
}

type suidItem struct {
	Binary    string   `json:"binary"`
	Dangerous bool     `json:"dangerous"`
	Writable  bool     `json:"writable"`
	Exploits  []string `json:"exploits,omitempty"`
	Owner     string   `json:"owner"`
}

type writableItem struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	InPath   bool   `json:"in_path,omitempty"`
}

type capItem struct {
	File         string `json:"file"`
	Capabilities string `json:"capabilities"`
	Dangerous    bool   `json:"dangerous"`
	Severity     string `json:"severity"`
}

func (l *LinPEAS) execute() *peasResult {
	hostname, _ := os.Hostname()
	r := &peasResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hostname:  hostname,
	}

	r.SudoChecks = checkSudoPrivs()
	r.SUIDBinaries = findSUID()
	r.Writable = checkWritable()
	r.CronVulns = checkCron()
	r.KernelExp = checkKernelExploits()
	r.Capabilities = checkCapabilities()

	// Summary
	summary := make(map[string]int)
	for _, w := range r.Writable {
		if w.Severity == "CRITICAL" {
			summary["critical"]++
		}
	}
	dangerousSUID := 0
	for _, s := range r.SUIDBinaries {
		if s.Dangerous {
			dangerousSUID++
		}
	}
	summary["high"] = dangerousSUID + len(r.CronVulns)
	summary["medium"] = len(r.KernelExp)
	r.Summary = summary

	return r
}

func checkSudoPrivs() []checkItem {
	var items []checkItem
	out, err := exec.Command("sudo", "-l").CombinedOutput()
	if err == nil && strings.Contains(string(out), "may run") {
		items = append(items, checkItem{
			Type:        "SUDO_PRIVS",
			Severity:    "HIGH",
			Description: "User has sudo privileges",
			Details:     string(out),
		})
	}
	data, err := os.ReadFile("/etc/sudoers")
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "ALL=(ALL)") && !strings.HasPrefix(line, "#") {
				items = append(items, checkItem{
					Type:        "SUDOERS_ALL",
					Severity:    "HIGH",
					Description: "User in sudoers with ALL privileges: " + line,
				})
			}
		}
	}
	return items
}

func findSUID() []suidItem {
	var items []suidItem
	dangerousMap := map[string][]string{
		"nmap":   {"--interactive mode escape"},
		"find":   {"-exec command execution"},
		"awk":    {"system() function"},
		"perl":   {"-e command execution"},
		"python": {"-c command execution"},
		"ruby":   {"-e command execution"},
		"bash":   {"-p privilege mode"},
		"sh":     {"-p privilege mode"},
	}

	err := filepath.Walk("/", func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if fi.Mode()&os.ModeSetuid == 0 {
			return nil
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		base := filepath.Base(path)
		exploits := dangerousMap[base]
		writable := fi.Mode().Perm()&0002 != 0
		owner := "unknown"
		if sys := fi.Sys(); sys != nil {
			if st, ok := sys.(*syscall.Stat_t); ok {
				owner = strconv.Itoa(int(st.Uid))
			}
		}
		items = append(items, suidItem{
			Binary:    path,
			Dangerous: exploits != nil,
			Writable:  writable,
			Exploits:  exploits,
			Owner:     owner,
		})
		return nil
	})
	_ = err
	if len(items) > 30 {
		items = items[:30]
	}
	return items
}

func checkWritable() []writableItem {
	var items []writableItem
	sensitive := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/etc/crontab", "/etc/init.d",
	}
	for _, p := range sensitive {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.Mode().Perm()&0002 != 0 {
			items = append(items, writableItem{
				Path:     p,
				Type:     "sensitive_file",
				Severity: "CRITICAL",
			})
		}
	}
	return items
}

func checkCron() []checkItem {
	var items []checkItem
	data, err := os.ReadFile("/etc/crontab")
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				script := parts[len(parts)-1]
				if fi, err := os.Stat(script); err == nil && fi.Mode().Perm()&0002 != 0 {
					items = append(items, checkItem{
						Type:        "WRITABLE_CRON_SCRIPT",
						Severity:    "CRITICAL",
						Description: fmt.Sprintf("Writable cron script: %s", script),
						Details:     line,
					})
				}
			}
		}
	}
	return items
}

func checkKernelExploits() []checkItem {
	var items []checkItem
	kernel := runtime.GOOS + "/" + runtime.GOARCH

	known := []struct {
		Name string
		Desc string
	}{
		{"DirtyCow", "CVE-2016-5195"},
		{"PwnKit", "CVE-2021-4034"},
		{"DirtyPipe", "CVE-2022-0847"},
		{"CopyFail", "CVE-2026-31431"},
	}
	for _, k := range known {
		items = append(items, checkItem{
			Type:        "KERNEL_EXPLOIT",
			Severity:    "MEDIUM",
			Description: fmt.Sprintf("%s (%s) - kernel: %s", k.Name, k.Desc, kernel),
		})
	}
	return items
}

func checkCapabilities() []capItem {
	var items []capItem
	dangerousCaps := []string{"cap_setuid", "cap_setgid", "cap_sys_admin", "cap_sys_ptrace"}

	out, err := exec.Command("getcap", "-r", "/").CombinedOutput()
	if err != nil {
		return items
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		fpath := strings.TrimRight(parts[0], ":")
		caps := strings.Join(parts[1:], " ")
		dangerous := false
		for _, dc := range dangerousCaps {
			if strings.Contains(caps, dc) {
				dangerous = true
				break
			}
		}
		severity := "LOW"
		if dangerous {
			severity = "HIGH"
		}
		items = append(items, capItem{
			File:         fpath,
			Capabilities: caps,
			Dangerous:    dangerous,
			Severity:     severity,
		})
	}
	if len(items) > 20 {
		items = items[:20]
	}
	return items
}
