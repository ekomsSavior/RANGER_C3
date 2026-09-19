//go:build windows

package payloads

import "os"

// fileOwner returns the numeric owner of a file. Not implemented on Windows.
func fileOwner(fi os.FileInfo) string { return "unknown" }

// diskSpace returns the total and free bytes for the filesystem containing
// path. Not implemented on Windows.
func diskSpace(path string) (uint64, uint64, bool) { return 0, 0, false }

// killProcess terminates the process with the given pid.
func killProcess(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
