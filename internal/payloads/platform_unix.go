//go:build !windows

package payloads

import (
	"os"
	"strconv"
	"syscall"
)

// fileOwner returns the numeric owner (uid) of a file, or "unknown" if unavailable.
func fileOwner(fi os.FileInfo) string {
	if sys := fi.Sys(); sys != nil {
		if st, ok := sys.(*syscall.Stat_t); ok {
			return strconv.Itoa(int(st.Uid))
		}
	}
	return "unknown"
}

// diskSpace returns the total and free bytes for the filesystem containing path.
func diskSpace(path string) (total, free uint64, ok bool) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, false
	}
	return stat.Blocks * uint64(stat.Bsize), stat.Bfree * uint64(stat.Bsize), true
}

// killProcess sends SIGKILL to the given pid.
func killProcess(pid int) error {
	return syscall.Kill(pid, syscall.SIGKILL)
}
