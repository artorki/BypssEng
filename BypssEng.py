# artorki

import os
import sys
import time
import socket
import ssl
import random
import json
import subprocess
import platform
import asyncio
import ctypes
import shutil
import logging
import logging.handlers
import datetime
import signal
import atexit
import re
import ipaddress
import argparse
import inspect

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PACKAGE_DIR = os.path.join(SCRIPT_DIR, "bypsseng")
if PACKAGE_DIR not in sys.path:
    sys.path.insert(0, PACKAGE_DIR)

from config.models import CONFIG
from engine.orchestrator import Orchestrator
from engine.models import DecisionExplanation
from core.logger import log, Colors
from core.network import get_resolver
from core.utils import parse_config_link, find_binary, get_proto_prefix, atomic_write_json
from runtime.process import pm
from runtime.ports import setup_dynamic_ports, release_reserved_ports
from strategies.registry import get_strategy
from decision.scorer import score_strategy
import telemetry.storage as telemetry
import aiohttp

if platform.system().lower() == 'windows':
    import asyncio.proactor_events
    import asyncio.base_subprocess
    def _patched_del(self, *args, **kwargs):
        try: self.close()
        except (RuntimeError, ValueError): pass
    if hasattr(asyncio.proactor_events, '_ProactorBasePipeTransport'): asyncio.proactor_events._ProactorBasePipeTransport.__del__ = _patched_del
    if hasattr(asyncio.base_subprocess, 'BaseSubprocessTransport'): asyncio.base_subprocess.BaseSubprocessTransport.__del__ = _patched_del

APP_DIR = PACKAGE_DIR
BIN_DIR = os.path.join(APP_DIR, "bin")
CORE_DIR = os.path.join(APP_DIR, "core")
DATA_DIR = os.path.join(APP_DIR, "Data")
os.makedirs(DATA_DIR, exist_ok=True)

log_handler = logging.handlers.RotatingFileHandler(filename=os.path.join(DATA_DIR, 'network_analyzer.log'), maxBytes=5*1024*1024, backupCount=3)
logging.basicConfig(handlers=[log_handler], level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger("NetAnalyzer")

BINARY_PATHS = {
    "xray": find_binary("xray", BIN_DIR), "hysteria": find_binary("hysteria", BIN_DIR),
    "tor": find_binary("tor", BIN_DIR), "snowflake": find_binary("snowflake-client", BIN_DIR),
    "lyrebird": find_binary("lyrebird", BIN_DIR), "tuic": find_binary("tuic", BIN_DIR),
    "naive": find_binary("naive", BIN_DIR), "psiphon": find_binary("psiphon-tunnel-core", BIN_DIR),
    "dnstt-client": find_binary("dnstt-client", BIN_DIR),
}
UNIFIED_CONFIG_FILE = os.path.join(DATA_DIR, "cnfg.json")
WORKING_CONFIGS_CACHE = os.path.join(DATA_DIR, "working_configs.cache")
STATE_FILE = os.path.join(DATA_DIR, "state.json")
LOCK_FILE = os.path.join(DATA_DIR, "engine.lock")
REPORT_FILE = os.path.join(DATA_DIR, "network_report.json")

lock_fd = None
DIAGNOSE_ONLY = False
latency_sem = asyncio.Semaphore(10)
LOCAL_SOCKS_PORT = 10808
LOCAL_HTTP_PORT = 10809

def acquire_lock():
    global lock_fd
    lock_fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR)
    try:
        if platform.system().lower() == 'windows': import msvcrt; msvcrt.locking(lock_fd, msvcrt.LK_NBLCK, 1)
        else: import fcntl; fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, IOError): print("Another instance is already running. Exiting."); sys.exit(0)

def release_lock():
    global lock_fd
    if lock_fd:
        try:
            if platform.system().lower() == 'windows': import msvcrt; msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
            else: import fcntl; fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
            if os.path.exists(LOCK_FILE): os.remove(LOCK_FILE)
        except Exception: pass
        finally: lock_fd = None

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f: return json.load(f)
        except Exception: return {}
    return {}

def save_state(state): atomic_write_json(STATE_FILE, state)

def cleanup_child_processes():
    pm.cleanup_child_processes()
    try:
        state = load_state()
        if state.get('dns_changed'):
            try: loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop); loop.run_until_complete(restore_system_dns()); loop.close()
            except Exception as e: logger.error(f"DNS restore in cleanup failed: {e}")
        if state.get('proxy_backed_up'):
            try: loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop); loop.run_until_complete(restore_system_proxy()); loop.close()
            except Exception as e: logger.error(f"Proxy restore in cleanup failed: {e}")
    except Exception: pass
    release_reserved_ports(); release_lock()

atexit.register(cleanup_child_processes)

def check_dependencies():
    required = ["xray", "hysteria", "tor", "tuic", "naive"]
    missing = [n for n in required if not BINARY_PATHS.get(n)]
    if missing: log(f"Warning: The following core binaries are missing: {', '.join(missing)}", "WARN")
    if not BINARY_PATHS.get("snowflake") and not BINARY_PATHS.get("lyrebird"): log("Warning: Pluggable transports missing.", "WARN")
    if not BINARY_PATHS.get("psiphon"): log("Warning: Psiphon binary is missing.", "WARN")
    if not BINARY_PATHS.get("dnstt-client"): log("Warning: Dnstt-client binary is missing.", "WARN")
    if not missing and (BINARY_PATHS.get("snowflake") or BINARY_PATHS.get("lyrebird")): log("All dependencies are present.", "PASS")

def is_root_or_admin():
    if platform.system().lower() == 'windows':
        try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except: return False
    return hasattr(os, 'geteuid') and os.geteuid() == 0

async def get_default_interface():
    system = platform.system().lower()
    if system == 'windows':
        proc = await asyncio.create_subprocess_exec('powershell', '-Command', 'Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -ExpandProperty InterfaceAlias', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate(); return stdout.decode().strip().split('\n')[0].strip()
    elif system == 'darwin':
        try:
            route_proc = await asyncio.create_subprocess_exec('route', '-n', 'get', 'default', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await route_proc.communicate(); output = stdout.decode(); iface = "en0"
            if "interface:" in output: iface = output.split("interface:")[1].split()[0]
            svc_proc = await asyncio.create_subprocess_exec('networksetup', '-listallhardwareports', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await svc_proc.communicate(); lines = stdout.decode().splitlines(); current_hw = None
            for line in lines:
                if "Hardware Port:" in line: current_hw = line.replace("Hardware Port: ", "").strip()
                elif "Device: " + iface in line: return current_hw
            return "Wi-Fi"
        except Exception: return "Wi-Fi"
    else:
        proc = await asyncio.create_subprocess_exec('ip', 'route', 'show', 'default', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate(); output = stdout.decode().strip()
        return output.split("dev")[1].split()[0] if "dev" in output else "eth0"

def extract_dns_ips(text):
    ips = []
    for line in text.splitlines():
        if "DNS Servers" in line or "Statically Configured DNS" in line or "Dynamically Configured DNS" in line:
            for token in re.findall(r'[^\s,;]+', line):
                try: ipaddress.ip_address(token); ips.append(token)
                except ValueError: pass
    if not ips:
        for token in re.findall(r'[^\s,;]+', text):
            try: ipaddress.ip_address(token); ips.append(token)
            except ValueError: pass
    return ips

async def get_current_dns():
    system = platform.system().lower(); interface = await get_default_interface()
    try:
        if system == 'windows':
            v4_out = ""; v6_out = ""
            try:
                p1 = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'show', 'dns', f'name="{interface}"', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, _ = await p1.communicate(); v4_out = stdout.decode()
            except: pass
            try:
                p2 = await asyncio.create_subprocess_exec('netsh', 'interface', 'ipv6', 'show', 'dns', f'name="{interface}"', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, _ = await p2.communicate(); v6_out = stdout.decode()
            except: pass
            return json.dumps({"v4_mode": "DHCP" if "DHCP" in v4_out else "STATIC", "v4_servers": extract_dns_ips(v4_out), "v6_mode": "DHCP" if "DHCP" in v6_out else "STATIC", "v6_servers": extract_dns_ips(v6_out)})
        elif system == 'darwin':
            proc = await asyncio.create_subprocess_exec('networksetup', '-getdnsservers', interface, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await proc.communicate(); out = stdout.decode().strip(); return out if out else "EMPTY"
        else:
            if shutil.which('resolvectl'):
                proc = await asyncio.create_subprocess_exec('resolvectl', 'dns', interface, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, _ = await proc.communicate(); out = stdout.decode().strip(); ips = extract_dns_ips(out); return " ".join(ips) if ips else "EMPTY"
            return "EMPTY"
    except Exception: return "EMPTY"

async def restore_system_dns():
    state = load_state()
    if not state.get('dns_changed'): return True
    interface = state.get('interface') or await get_default_interface()
    if not interface: return False
    original_dns = state.get('original_dns', ""); system = platform.system().lower()
    try:
        if system == 'windows':
            try: dns_data = json.loads(original_dns)
            except Exception: state['dns_changed'] = False; state['dns_backed_up'] = False; save_state(state); return False
            if dns_data.get("v4_mode") == "DHCP":
                p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'set', 'dns', f'name="{interface}"', 'source=dhcp', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p.communicate()
            else:
                v4_ips = dns_data.get("v4_servers", [])
                if v4_ips:
                    p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'set', 'dns', f'name="{interface}"', 'static', v4_ips[0], 'primary', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p.communicate()
                    for i, ip in enumerate(v4_ips[1:], start=2):
                        p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'add', 'dns', f'name="{interface}"', ip, f'index={i}', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p.communicate()
            p_flush = await asyncio.create_subprocess_exec('ipconfig', '/flushdns', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p_flush.communicate()
        elif system == 'darwin':
            if original_dns and "There aren't any DNS Servers" not in original_dns:
                dns_list = original_dns.split()
                p = await asyncio.create_subprocess_exec('networksetup', '-setdnsservers', interface, *dns_list, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p.communicate()
            else:
                p = await asyncio.create_subprocess_exec('networksetup', '-setdnsservers', interface, 'empty', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p.communicate()
        else:
            if shutil.which('resolvectl'):
                if original_dns and original_dns != "EMPTY":
                    dns_ips = original_dns.split()
                    p = await asyncio.create_subprocess_exec('resolvectl', 'dns', interface, *dns_ips, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p.communicate()
                else:
                    p = await asyncio.create_subprocess_exec('resolvectl', 'revert', interface, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p.communicate()
        state['dns_changed'] = False; state['dns_backed_up'] = False; state.pop('original_dns', None); save_state(state)
        log("System DNS restored to original settings.", "PASS"); return True
    except Exception as e: logger.error(f"DNS restore error: {e}"); return False

async def get_current_proxy():
    system = platform.system().lower()
    try:
        if system == 'windows':
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, winreg.KEY_READ)
            enable, _ = winreg.QueryValueEx(key, 'ProxyEnable'); server = ""; override = ""
            try: server, _ = winreg.QueryValueEx(key, 'ProxyServer')
            except: pass
            try: override, _ = winreg.QueryValueEx(key, 'ProxyOverride')
            except: pass
            winreg.CloseKey(key); return {"valid": True, "enabled": bool(enable), "server": server, "override": override}
        elif system == 'darwin':
            interface = await get_default_interface()
            proc = await asyncio.create_subprocess_exec('networksetup', '-getwebproxy', interface, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await proc.communicate(); out = stdout.decode()
            enabled = "Enabled: Yes" in out; server = re.search(r"Server: (\S+)", out); port = re.search(r"Port: (\d+)", out)
            sproc = await asyncio.create_subprocess_exec('networksetup', '-getsecurewebproxy', interface, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            sout, _ = await sproc.communicate(); sout_str = sout.decode()
            s_enabled = "Enabled: Yes" in sout_str; s_server = re.search(r"Server: (\S+)", sout_str); s_port = re.search(r"Port: (\d+)", sout_str)
            return {"valid": True, "web_enabled": enabled, "secure_enabled": s_enabled, "server": f"{server.group(1)}:{port.group(1)}" if server and port else "", "secure_server": f"{s_server.group(1)}:{s_port.group(1)}" if s_server and s_port else ""}
        else:
            if not shutil.which('gsettings'): return {"valid": False, "enabled": False, "server": ""}
            mode_proc = await asyncio.create_subprocess_exec('gsettings', 'get', 'org.gnome.system.proxy', 'mode', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await mode_proc.communicate(); mode = stdout.decode().strip().strip("'")
            if mode == 'manual':
                host_proc = await asyncio.create_subprocess_exec('gsettings', 'get', 'org.gnome.system.proxy.http', 'host', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                host, _ = await host_proc.communicate()
                port_proc = await asyncio.create_subprocess_exec('gsettings', 'get', 'org.gnome.system.proxy.http', 'port', stdout=subprocess.PIPE, stderr=subprocessPIPE)
                port, _ = await port_proc.communicate()
                http_host = host.decode().strip().strip("'")
                return {"valid": True, "enabled": True, "server": f"{http_host}:{port.decode().strip().strip(chr(39))}" if http_host else ""}
            return {"valid": True, "enabled": False, "server": ""}
    except Exception: return {"valid": False, "enabled": False, "server": ""}

async def restore_system_proxy():
    state = load_state()
    if not state.get('proxy_backed_up'): return True
    original = state.get('original_proxy', {})
    if not original.get("valid"): return False
    system = platform.system().lower()
    try:
        if system == 'windows':
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, winreg.KEY_ALL_ACCESS)
            if original.get("enabled"): winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
            else: winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            if original.get("server"): winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, original["server"])
            winreg.CloseKey(key)
            ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0); ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
        elif system == 'darwin':
            interface = await get_default_interface()
            if original.get("web_enabled") and original.get("server"):
                host, port = original["server"].rsplit(":", 1); host = host.strip("[]")
                p = await asyncio.create_subprocess_exec('networksetup', '-setwebproxy', interface, host, port, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p.communicate()
            else:
                p = await asyncio.create_subprocess_exec('networksetup', '-setwebproxystate', interface, 'off', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p.communicate()
        else:
            if not shutil.which('gsettings'): return False
            cmds = [['gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'none']] if not original.get("enabled") else [['gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'manual']]
            for cmd in cmds:
                p = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p.communicate()
        state['proxy_backed_up'] = False; state['proxy_enabled'] = original.get("enabled", False); state.pop("original_proxy", None); save_state(state)
        log("System proxy restored to original settings.", "PASS"); return True
    except Exception as e: logger.error(f"Proxy restore error: {e}"); return False

async def set_system_proxy(enable, port=None):
    if DIAGNOSE_ONLY: return True
    if not port: port = LOCAL_HTTP_PORT
    system = platform.system().lower(); state = load_state()
    if enable and not state.get('proxy_backed_up'):
        state['original_proxy'] = await get_current_proxy()
        if not state['original_proxy'].get("valid"): return False
        state['proxy_backed_up'] = True; save_state(state)
    try:
        if system == 'windows':
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, winreg.KEY_ALL_ACCESS)
            if enable:
                winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1); winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, f'127.0.0.1:{port}'); winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, 'localhost;127.0.0.1;<local>')
            else: winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0); ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
        elif system == 'darwin':
            interface = await get_default_interface()
            if enable:
                p1 = await asyncio.create_subprocess_exec('networksetup', '-setwebproxy', interface, '127.0.0.1', str(port), stdout=subprocess.PIPE, stderr=subprocess.PIPE); await p1.communicate()
                p2 = await asyncio.create_subprocess_exec('networksetup', '-setsecurewebproxy', interface, '127.0.0.1', str(port), stdout=subprocess.PIPE, stderr=subprocess.PIPE); await p2.communicate()
            else:
                p1 = await asyncio.create_subprocess_exec('networksetup', '-setwebproxystate', interface, 'off', stdout=subprocess.PIPE, stderr=subprocess.PIPE); await p1.communicate()
                p2 = await asyncio.create_subprocess_exec('networksetup', '-setsecurewebproxystate', interface, 'off', stdout=subprocess.PIPE, stderr=subprocess.PIPE); await p2.communicate()
        else:
            if not shutil.which('gsettings'): return False
            if enable: cmds = [['gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'manual'], ['gsettings', 'set', 'org.gnome.system.proxy.http', 'host', '127.0.0.1'], ['gsettings', 'set', 'org.gnome.system.proxy.http', 'port', str(port)]]
            else: cmds = [['gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'none']]
            for cmd in cmds:
                p = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE); await p.communicate()
        state = load_state(); state['proxy_enabled'] = enable; save_state(state); return True
    except Exception: return False

def load_unified_config():
    if not os.path.exists(UNIFIED_CONFIG_FILE):
        template = {"configs": [], "subscription_urls": [], "warp": None, "cloudflare_worker": None, "psiphon": None, "dnstt": None}
        atomic_write_json(UNIFIED_CONFIG_FILE, template); return template
    try:
        with open(UNIFIED_CONFIG_FILE, "r", encoding="utf-8") as f: return json.load(f)
    except Exception: return {"configs": [], "subscription_urls": [], "warp": None, "cloudflare_worker": None, "psiphon": None, "dnstt": None}

def load_working_configs():
    if not os.path.exists(WORKING_CONFIGS_CACHE): return []
    with open(WORKING_CONFIGS_CACHE, "r") as f: return [line.strip() for line in f.readlines() if line.strip()]

async def fetch_fresh_configs(wait=True):
    original_cwd = os.getcwd()
    try:
        os.chdir(DATA_DIR)
        sys.path.insert(0, CORE_DIR)
        import cnfg
        log("Running cnfg as module...", "SOL")
        if hasattr(cnfg, 'main'):
            old_mtime = os.path.getmtime(UNIFIED_CONFIG_FILE) if os.path.exists(UNIFIED_CONFIG_FILE) else 0
            if inspect.iscoroutinefunction(cnfg.main): await cnfg.main()
            else: await asyncio.get_event_loop().run_in_executor(None, cnfg.main)
            new_mtime = os.path.getmtime(UNIFIED_CONFIG_FILE) if os.path.exists(UNIFIED_CONFIG_FILE) else 0
            if new_mtime > old_mtime: log("Fresh configs fetched successfully via module!", "PASS"); return True
            else: log("Module ran but no new configs generated.", "WARN"); return False
    except ImportError: pass
    except Exception as e: logger.error(f"Module cnfg execution failed: {e}. Falling back to subprocess.")
    finally:
        os.chdir(original_cwd)
        if CORE_DIR in sys.path: sys.path.remove(CORE_DIR)

    cnfg_script = os.path.join(CORE_DIR, "cnfg.py")
    if os.path.exists(cnfg_script): cmd = [sys.executable, cnfg_script]
    else: log("cnfg.py not found in core directory! Cannot auto-fetch.", "FAIL"); return False

    log("Running cnfg to get fresh configs via subprocess...", "SOL")
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if platform.system().lower() == 'windows' else 0
        old_mtime = os.path.getmtime(UNIFIED_CONFIG_FILE) if os.path.exists(UNIFIED_CONFIG_FILE) else 0
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=creationflags, cwd=DATA_DIR)
        if wait:
            try: stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=45)
            except asyncio.TimeoutError:
                log("cnfg took too long (45s). Terminating.", "WARN")
                try: proc.terminate(); await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    try: proc.kill()
                    except: pass
                return False
            new_mtime = os.path.getmtime(UNIFIED_CONFIG_FILE) if os.path.exists(UNIFIED_CONFIG_FILE) else 0
            if proc.returncode == 0 and new_mtime > old_mtime: log("Fresh configs fetched successfully!", "PASS"); return True
            else: err = stderr.decode(errors='ignore'); log(f"cnfg exited with error or no update: {err}", "WARN"); return False
        else:
            async def bg_task():
                try:
                    await proc.communicate()
                    new_mtime = os.path.getmtime(UNIFIED_CONFIG_FILE) if os.path.exists(UNIFIED_CONFIG_FILE) else 0
                    if proc.returncode == 0 and new_mtime > old_mtime: log("Background cnfg fetch completed successfully.", "PASS")
                    else: log("Background cnfg fetch finished with errors or no update.", "WARN")
                except Exception as e: logger.error(f"Background cnfg fetch failed: {e}")
            asyncio.create_task(bg_task()); log("Background config fetch started.", "INFO"); return "started"
    except Exception as e: log(f"Failed to run cnfg: {e}", "WARN"); return False

def generate_network_report(states, applied_bypass="none", diagnosis=None, selected_method=None):
    if not diagnosis: diagnosis = []
    if not selected_method: selected_method = "unknown"
    
    confidence = "low"; severity_score = 30
    if selected_method == "healthy": confidence = "high"; severity_score = 100
    elif "blackout" in diagnosis: severity_score = 0
    elif "intl_transit_cut" in diagnosis: severity_score = 10
    elif "dpi_aggressive" in diagnosis or states.get('dpi') == 'dpi_aggressive': severity_score = 20
    elif "throttling" in diagnosis: severity_score = 40
    elif "dpi_rst" in diagnosis or states.get('dpi') == 'dpi_rst': severity_score = 50
    elif states.get('speed') == 'speed_slow': severity_score = 70
    elif selected_method in ["tor_proxy", "tor_snowflake", "psiphon", "dnstt"]: confidence = "medium"
    elif selected_method in ["vless", "trojan", "hysteria2", "hy2", "tuic", "warp", "cf_worker", "balancer"]:
        if "undetermined" in diagnosis or any(v == 'unknown' for v in states.values() if isinstance(v, str)): confidence = "medium"
        else: confidence = "high"
            
    explanation = DecisionExplanation(selected=selected_method, alternatives={}, evidence=diagnosis if isinstance(diagnosis, list) else [str(diagnosis)])
    verdict = {
        "diagnosis": diagnosis, "selected_method": selected_method, "confidence": confidence,
        "severity_score": severity_score, "explanation": {"selected": explanation.selected, "alternatives": explanation.alternatives, "evidence": explanation.evidence}
    }
    report = {"timestamp": datetime.datetime.now().isoformat(), "network_states": states, "applied_bypass": applied_bypass, "verdict": verdict}
    try: atomic_write_json(REPORT_FILE, report)
    except Exception as e: logger.error(f"Report write failed: {e}")
    return verdict

async def execute_bypass_and_connect(creds, dpi_state='none'):
    global LOCAL_SOCKS_PORT, LOCAL_HTTP_PORT
    async with pm.strategy_lock:
        old_proc = pm.active_proc if (pm.active_proc and pm.active_proc.returncode is None) else None
        old_proxy_active = old_proc is not None
        old_socks_port = LOCAL_SOCKS_PORT; old_http_port = LOCAL_HTTP_PORT

        LOCAL_SOCKS_PORT, LOCAL_HTTP_PORT = setup_dynamic_ports()
        log_tasks = []

        async def restore_state_on_failure():
            for t in log_tasks:
                try: t.cancel()
                except Exception: pass
            if pm.active_proc and pm.active_proc.returncode is None and pm.active_proc is not old_proc:
                try: pm.active_proc.terminate(); await asyncio.wait_for(pm.active_proc.wait(), timeout=3)
                except Exception:
                    try: pm.active_proc.kill()
                    except Exception as e: logger.error(f"Kill process error: {e}")
            release_reserved_ports()
            if old_proxy_active:
                pm.active_proc = old_proc; LOCAL_SOCKS_PORT = old_socks_port; LOCAL_HTTP_PORT = old_http_port
            else:
                pm.active_proc = None; await restore_system_proxy()

        strategy = get_strategy(creds, None, dpi_state, LOCAL_SOCKS_PORT, LOCAL_HTTP_PORT, DATA_DIR, BINARY_PATHS)
        if not strategy: await restore_state_on_failure(); return False

        config_file, binary_name = await strategy.prepare()
        if not config_file: await restore_state_on_failure(); return False

        binary_path = strategy.get_binary_path()
        abs_config_file = os.path.join(DATA_DIR, config_file)
        cmd_args = strategy.get_command_args(binary_path, abs_config_file)

        try:
            release_reserved_ports()
            pm.active_proc = await asyncio.create_subprocess_exec(*cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc = pm.active_proc
            
            async def tail_logs(stream, prefix):
                while True:
                    line = await stream.readline()
                    if not line: break
                    decoded_line = line.decode(errors='ignore').strip()
                    if any(k in decoded_line.lower() for k in ["error", "warn", "failed"]): log(f"[{binary_name}] {decoded_line}", "INFO")
            log_tasks.append(asyncio.create_task(tail_logs(proc.stdout, "STDOUT")))
            log_tasks.append(asyncio.create_task(tail_logs(proc.stderr, "STDERR")))
            
            await asyncio.sleep(3)
            proxy = f"http://127.0.0.1:{LOCAL_HTTP_PORT}"
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
                success = False
                for url in ["https://cp.cloudflare.com/generate_204", "https://www.google.com/generate_204"]:
                    if proc.returncode is not None: break
                    try:
                        async with session.get(url, proxy=proxy) as resp:
                            if resp.status in [204, 200, 301, 302]:
                                log(f"Successfully connected via {creds['protocol'].upper()}!", "PASS")
                                if not await set_system_proxy(True, LOCAL_HTTP_PORT): await restore_state_on_failure(); return False
                                if old_proc and old_proc.returncode is None: old_proc.terminate()
                                success = True; break
                    except Exception: continue
                if not success:
                    log(f"Proxy failed to connect.", "FAIL"); await restore_state_on_failure(); return False
                return True
        except Exception as e:
            log(f"Failed to start {binary_name}: {e}", "ERROR")
            await restore_state_on_failure(); return False

async def bypass_executor_wrapper(states, diagnosis_result):
    log(f"Executing bypass based on diagnosis: {diagnosis_result.condition}", "SOL")
    
    if not os.path.exists(UNIFIED_CONFIG_FILE) or os.path.getsize(UNIFIED_CONFIG_FILE) < 30:
        log("No valid cnfg.json found. Running cnfg to fetch configs...", "SOL")
        await fetch_fresh_configs(wait=True)
        
    unified_cfg = load_unified_config()
    config_links = load_working_configs() if os.path.exists(WORKING_CONFIGS_CACHE) else unified_cfg.get("configs", [])
    parsed_configs = [parse_config_link(link) for link in config_links]
    valid_configs = [c for c in parsed_configs if c["protocol"] != "unsupported"]
    if unified_cfg.get("warp"): valid_configs.append({"protocol": "warp", "warp_data": unified_cfg["warp"]})
    if unified_cfg.get("cloudflare_worker"): valid_configs.append({"protocol": "cloudflare_worker", "worker_data": unified_cfg["cloudflare_worker"]})
    valid_configs.extend([{"protocol": "tor_proxy"}, {"protocol": "tor_snowflake"}])

    scored_candidates = []
    for c in valid_configs:
        score = await score_strategy(c["protocol"], states)
        scored_candidates.append((c, score))
    scored_candidates.sort(key=lambda x: x[1].score, reverse=True)
    
    alternatives = {}
    selected_strategy = None
    explanation_evidence = []
    
    for creds, score in scored_candidates:
        if score.score > 0.1:
            log(f"Attempting strategy: {creds['protocol']} (Score: {score.score:.2f})", "INFO")
            success = await execute_bypass_and_connect(creds, dpi_state=states.get('dpi'))
            if success:
                selected_strategy = creds["protocol"]
                explanation_evidence = score.reasons
                await telemetry.record_strategy_outcome(creds["protocol"], diagnosis_result.condition, True)
                break
            else:
                alternatives[creds["protocol"]] = score.score
                await telemetry.record_strategy_outcome(creds["protocol"], diagnosis_result.condition, False)
                
    if selected_strategy:
        generate_network_report(states, f"connected_via_{selected_strategy}", [diagnosis_result.condition], selected_strategy)
        explanation = DecisionExplanation(selected=selected_strategy, alternatives=alternatives, evidence=explanation_evidence)
        return True, explanation
    return False, None

async def main():
    import datetime
    current_year = datetime.datetime.now().year
    if current_year < 2025: log(f"CRITICAL: System time is set to {current_year}.", "ERROR")
    
    await telemetry.init_db()
    await telemetry.cleanup_old_logs()
    acquire_lock(); pm.kill_stale_processes(); check_dependencies()
    
    log("Performing startup recovery policy...", "SOL")
    state = load_state()
    if state.get('proxy_backed_up') and not await restore_system_proxy(): sys.exit(1)
    if state.get('dns_changed') and not await restore_system_dns(): sys.exit(1)

    print(f"{Colors.BOLD}Advanced Analyzer & Auto-Bypass Engine Started (CLI Mode).{Colors.ENDC}\n")
    orchestrator = Orchestrator(APP_DIR, bypass_executor_wrapper, LOCAL_HTTP_PORT)
    try: await orchestrator.run()
    finally: await telemetry.close_db()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--diagnose-only", action="store_true")
    args = parser.parse_args()
    if args.diagnose_only: DIAGNOSE_ONLY = True

    try:
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        try: loop.run_until_complete(main())
        finally:
            pending = asyncio.all_tasks(loop=loop)
            for task in pending: task.cancel()
            if pending: loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens()); loop.close()
    except KeyboardInterrupt: log("Exiting...", "INFO")
    finally: pm.cleanup_child_processes(); sys.exit(0)
