package implantpkg

import (
	"bytes"
	"os/exec"
	"time"
)

func execCommandGeneric(shell, flag, cmd string) (string, error) {
	c := exec.Command(shell, flag, cmd)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	done := make(chan error, 1)
	go func() {
		done <- c.Run()
	}()

	select {
	case err := <-done:
		out := stdout.String()
		if stderr.Len() > 0 {
			out += "\nSTDERR: " + stderr.String()
		}
		if err != nil {
			return out, err
		}
		return out, nil
	case <-time.After(30 * time.Second):
		c.Process.Kill()
		return stdout.String(), nil
	}
}
