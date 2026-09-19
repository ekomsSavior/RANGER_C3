//go:build linux || darwin

package implantpkg

import "syscall"

type unixStatfs_t = syscall.Statfs_t

func statfs(path string, stat *unixStatfs_t) error {
	return syscall.Statfs(path, stat)
}

func execCommand(shell, flag, cmd string) (string, error) {
	return execCommandGeneric(shell, flag, cmd)
}
