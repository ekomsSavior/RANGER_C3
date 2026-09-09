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
	Register(&SysRecon{})
}

type SysRecon struct{}

func (s *SysRecon) Name() string     { return "sysrecon" }
func (s *SysRecon) Category() string { return "recon" }
func (s *SysRecon) Description() string {
	return "Full system enumeration (OS, kernel, users, processes, network, hardware, software, defenses)"
}

func (s *SysRecon) Execute(args map[string]string) ([]byte, error) {
	info := s.gatherSystemInfo()
	return MarshalJSON(info)
}

type sysInfo struct {
	Timestamp string            `json:"timestamp"`
	Hostname  string            `json:"hostname"`
	FQDN      string            `json:"fqdn"`
	OS        map[string]string `json:"os"`
	Kernel    string            `json:"kernel"`
	BootTime  string            `json:"boot_time"`
	Users     []userInfo        `json:"users"`
	Processes []procInfo        `json:"processes"`
	Network   networkInfo       `json:"network"`
	Hardware  hardwareInfo      `json:"hardware"`
	Software  softwareInfo      `json:"software"`
	Defenses  defenseInfo       `json:"defenses"`
}

type userInfo struct {
	Username string   `json:"username"`
	UID      int      `json:"uid"`
	GID      int      `json:"gid"`
	Home     string   `json:"home"`
	Shell    string   `json:"shell"`
	Groups   []string `json:"groups,omitempty"`
}

type procInfo struct {
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	User    string `json:"user,omitempty"`
	CPU     string `json:"cpu_percent,omitempty"`
	Memory  string `json:"memory_percent,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
}

type networkInfo struct {
	Interfaces  []ifaceInfo `json:"interfaces"`
	Connections []connInfo  `json:"connections"`
	Routing     []routeInfo `json:"routing"`
	DNS         []string    `json:"dns"`
	ARP         []string    `json:"arp"`
}

type ifaceInfo struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	MAC       string   `json:"mac,omitempty"`
}

type connInfo struct {
	FD     int    `json:"fd,omitempty"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
	Status string `json:"status"`
	PID    int    `json:"pid,omitempty"`
}

type routeInfo struct {
	Interface string `json:"interface"`
	Gateway   string `json:"gateway,omitempty"`
	Dest      string `json:"destination,omitempty"`
}

type hardwareInfo struct {
	CPU    cpuInfo    `json:"cpu"`
	Memory memoryInfo `json:"memory"`
	Disks  []diskInfo `json:"disks"`
}

type cpuInfo struct {
	Cores   int    `json:"cores"`
	Threads int    `json:"threads"`
	Model   string `json:"model"`
}

type memoryInfo struct {
	Total     uint64  `json:"total"`
	Available uint64  `json:"available"`
	Percent   float64 `json:"percent"`
}

type diskInfo struct {
	Device     string `json:"device"`
	Mountpoint string `json:"mountpoint"`
	Fstype     string `json:"fstype"`
	Total      uint64 `json:"total"`
	Used       uint64 `json:"used"`
	Free       uint64 `json:"free"`
	Percent    string `json:"percent"`
}

type softwareInfo struct {
	Packages []string `json:"packages"`
	Services []string `json:"services"`
	Cron     []string `json:"cron"`
}

type defenseInfo struct {
	SELinux   bool     `json:"selinux"`
	AppArmor  bool     `json:"apparmor"`
	Firewall  bool     `json:"firewall"`
	IDS       []string `json:"ids"`
	Antivirus []string `json:"antivirus"`
}

func (s *SysRecon) gatherSystemInfo() *sysInfo {
	hostname, _ := os.Hostname()
	return &sysInfo{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hostname:  hostname,
		FQDN:      getFQDN(),
		OS: map[string]string{
			"system":    runtime.GOOS,
			"arch":      runtime.GOARCH,
			"goVersion": runtime.Version(),
		},
		Kernel:    getKernelVersion(),
		BootTime:  getBootTime(),
		Users:     getUsers(),
		Processes: getProcesses(),
		Network:   getNetworkInfo(),
		Hardware:  getHardwareInfo(),
		Software:  getSoftwareInfo(),
		Defenses:  getDefenseInfo(),
	}
}

func getFQDN() string {
	out, err := exec.Command("hostname", "-f").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func getKernelVersion() string {
	data, err := os.ReadFile("/proc/sys/kernel/ostype")
	if err != nil {
		out, err := exec.Command("uname", "-a").Output()
		if err != nil {
			return runtime.GOOS
		}
		return strings.TrimSpace(string(out))
	}
	return strings.TrimSpace(string(data))
}

func getBootTime() string {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "btime ") {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				sec, err := strconv.ParseInt(parts[1], 10, 64)
				if err == nil {
					return time.Unix(sec, 0).UTC().Format(time.RFC3339)
				}
			}
		}
	}
	return ""
}

func getUsers() []userInfo {
	var users []userInfo
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return users
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 7 {
			uid, _ := strconv.Atoi(parts[2])
			gid, _ := strconv.Atoi(parts[3])
			users = append(users, userInfo{
				Username: parts[0],
				UID:      uid,
				GID:      gid,
				Home:     parts[5],
				Shell:    parts[6],
			})
		}
	}
	if len(users) > 50 {
		users = users[:50]
	}
	return users
}

func getProcesses() []procInfo {
	var procs []procInfo
	data, err := os.ReadFile("/proc")
	if err != nil {
		return procs
	}
	_ = data
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return procs
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		name := fmt.Sprintf("pid_%d", pid)
		if len(cmdline) > 0 {
			name = strings.ReplaceAll(string(cmdline), "\x00", " ")
		}
		procs = append(procs, procInfo{
			PID:     pid,
			Name:    filepath.Base(name),
			Cmdline: name,
		})
		count++
		if count >= 100 {
			break
		}
	}
	return procs
}

func getNetworkInfo() networkInfo {
	net := networkInfo{}
	// Interfaces via /proc/net/dev
	data, err := os.ReadFile("/proc/net/dev")
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.Contains(line, ":") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			iface := strings.TrimSpace(parts[0])
			net.Interfaces = append(net.Interfaces, ifaceInfo{
				Name:      iface,
				Addresses: getInterfaceIPs(iface),
			})
		}
	}
	// DNS
	dnsData, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(dnsData))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				net.DNS = append(net.DNS, line)
			}
		}
	}
	// ARP
	arpData, err := os.ReadFile("/proc/net/arp")
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(arpData))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.HasPrefix(line, "IP") && line != "" {
				net.ARP = append(net.ARP, line)
			}
		}
	}
	return net
}

func getInterfaceIPs(name string) []string {
	var addrs []string
	data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/address", name))
	if err == nil {
		addrs = append(addrs, "mac:"+strings.TrimSpace(string(data)))
	}
	out, err := exec.Command("ip", "-o", "-4", "addr", "show", name).Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "inet" && i+1 < len(fields) {
					addrs = append(addrs, fields[i+1])
				}
			}
		}
	}
	return addrs
}

func getHardwareInfo() hardwareInfo {
	h := hardwareInfo{}
	h.CPU.Cores = runtime.NumCPU()
	h.CPU.Threads = runtime.NumCPU()
	// CPU model
	cpuData, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(cpuData))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					h.CPU.Model = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}
	// Memory
	memData, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(memData))
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, _ := strconv.ParseUint(parts[1], 10, 64)
				switch {
				case strings.HasPrefix(line, "MemTotal:"):
					h.Memory.Total = val * 1024
				case strings.HasPrefix(line, "MemAvailable:"):
					h.Memory.Available = val * 1024
				}
			}
		}
		if h.Memory.Total > 0 {
			h.Memory.Percent = 100.0 * float64(h.Memory.Total-h.Memory.Available) / float64(h.Memory.Total)
		}
	}
	// Disks
	h.Disks = getDiskInfo()
	return h
}

func getDiskInfo() []diskInfo {
	var disks []diskInfo
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return disks
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		// Only physical filesystems
		if strings.HasPrefix(parts[0], "/dev/") {
			var stat syscall.Statfs_t
			err := syscall.Statfs(parts[1], &stat)
			if err != nil {
				continue
			}
			total := stat.Blocks * uint64(stat.Bsize)
			free := stat.Bfree * uint64(stat.Bsize)
			used := total - free
			percent := "0%"
			if total > 0 {
				percent = fmt.Sprintf("%.1f%%", 100.0*float64(used)/float64(total))
			}
			disks = append(disks, diskInfo{
				Device:     parts[0],
				Mountpoint: parts[1],
				Fstype:     parts[2],
				Total:      total,
				Used:       used,
				Free:       free,
				Percent:    percent,
			})
		}
	}
	return disks
}

func getSoftwareInfo() softwareInfo {
	sw := softwareInfo{}
	// Packages (dpkg)
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		out, err := exec.Command("dpkg", "-l").Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(out))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "ii") {
					sw.Packages = append(sw.Packages, line)
				}
			}
			if len(sw.Packages) > 50 {
				sw.Packages = sw.Packages[:50]
			}
		}
	}
	// Cron
	out, err := exec.Command("crontab", "-l").Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			sw.Cron = append(sw.Cron, scanner.Text())
		}
	}
	// Running services (systemd)
	svcOut, err := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-pager").Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(svcOut))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasSuffix(line, ".service") {
				sw.Services = append(sw.Services, line)
			}
		}
		if len(sw.Services) > 50 {
			sw.Services = sw.Services[:50]
		}
	}
	return sw
}

func getDefenseInfo() defenseInfo {
	d := defenseInfo{}
	// SELinux
	if _, err := os.Stat("/usr/sbin/sestatus"); err == nil {
		out, err := exec.Command("sestatus").Output()
		if err == nil {
			d.SELinux = strings.Contains(strings.ToLower(string(out)), "enabled")
		}
	}
	// AppArmor
	if _, err := os.Stat("/sys/module/apparmor/parameters/enabled"); err == nil {
		data, err := os.ReadFile("/sys/module/apparmor/parameters/enabled")
		if err == nil {
			d.AppArmor = strings.TrimSpace(string(data)) == "Y"
		}
	}
	// Firewall
	out, err := exec.Command("iptables", "-L", "-n").Output()
	if err == nil {
		d.Firewall = strings.Contains(string(out), "Chain INPUT")
	}
	return d
}
