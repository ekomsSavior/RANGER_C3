//go:build windows

package implantpkg

import (
	"syscall"
	"unsafe"
)

// statfsStats mirrors the unix statfs fields ranger reads on Linux so the
// shared statfs() callers compile unchanged; on Windows the values are
// populated from GetDiskFreeSpaceExW below.
type unixStatfs_t struct {
	Bsize  uint64
	Blocks uint64
}

func statfs(path string, stat *unixStatfs_t) error {
	// Use GetDiskFreeSpaceEx on Windows
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceEx := kernel32.NewProc("GetDiskFreeSpaceExW")

	pathPtr, _ := syscall.UTF16PtrFromString(path + "\\")
	var freeBytesAvailable, totalBytes, totalFreeBytes int64

	ret, _, _ := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if ret == 0 {
		return syscall.GetLastError()
	}

	stat.Blocks = uint64(totalBytes) / 4096
	stat.Bsize = 4096
	return nil
}

func execCommand(shell, flag, cmd string) (string, error) {
	return execCommandGeneric(shell, flag, cmd)
}
