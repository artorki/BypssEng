#artorki

import os
import sys
import time
import socket
import ssl
import random
import string
import json
import subprocess
import platform
import asyncio
import statistics
import ctypes
import shutil
import logging
import datetime
import signal
import atexit
import re
import base64
import hashlib
import inspect
import ipaddress
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse, parse_qs, unquote

if platform.system().lower() == 'windows':
    import asyncio.proactor_events
    import asyncio.base_subprocess

    def _patched_del(self, *args, **kwargs):
        try:
            self.close()
        except (RuntimeError, ValueError):
            pass

    if hasattr(asyncio.proactor_events, '_ProactorBasePipeTransport'):
        asyncio.proactor_events._ProactorBasePipeTransport.__del__ = _patched_del

    if hasattr(asyncio.base_subprocess, 'BaseSubprocessTransport'):
        asyncio.base_subprocess.BaseSubprocessTransport.__del__ = _patched_del

def get_app_dir():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return script_dir

APP_DIR = get_app_dir()
CORE_DIR = os.path.join(APP_DIR, "Core")
DATA_DIR = os.path.join(APP_DIR, "Data")
os.makedirs(DATA_DIR, exist_ok=True)

try:
    import aiohttp
except ImportError:
    print("Error: 'aiohttp' is not installed. Please run: pip install aiohttp")
    sys.exit(1)

try:
    import aiodns
    RESOLVER_CLASS = aiohttp.AsyncResolver
except ImportError:
    print("Warning: 'aiodns' is not installed. Using default resolver.")
    RESOLVER_CLASS = aiohttp.DefaultResolver

def get_resolver(nameservers=None):
    if RESOLVER_CLASS == aiohttp.DefaultResolver:
        try:
            return aiohttp.DefaultResolver(nameservers=nameservers)
        except TypeError:
            return aiohttp.DefaultResolver()
    return RESOLVER_CLASS(nameservers=nameservers)

if platform.system().lower() == 'windows':
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception as e:
        logging.error(f"Console mode error: {e}")

log_handler = RotatingFileHandler(
    filename=os.path.join(DATA_DIR, 'network_analyzer.log'),
    maxBytes=5*1024*1024,
    backupCount=3
)
logging.basicConfig(
    handlers=[log_handler],
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("NetAnalyzer")

xray_proc = None
dnstt_proc = None
xray_lock = asyncio.Lock()
latency_sem = asyncio.Semaphore(10)
speed_test_sem = asyncio.Semaphore(3)
_background_tasks = set()

LOCAL_SOCKS_PORT = 10808
LOCAL_HTTP_PORT = 10809
_port_sockets = []
LOCK_FILE = os.path.join(DATA_DIR, "engine.lock")
lock_fd = None

DEEP_SCAN_INTERVAL = 3600

def random_spider_x():
    paths = ["/", "", "/index.html", "/home", "/api/v1/status", "/static/img/logo.png", "/robots.txt", "/search?q=", "/en/", "/blog/"]
    return random.choice(paths)

def get_less_popular_sni():
    snis = [
        "www.samsung.com", "www.amd.com", "www.nvidia.com",
        "addons.mozilla.org", "www.icloud.com", "www.tesla.com",
        "www.lovelive-anime.jp", "www.cpanel.net"
    ]
    return random.choice(snis)

def acquire_lock():
    global lock_fd
    lock_fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR)
    try:
        if platform.system().lower() == 'windows':
            import msvcrt
            msvcrt.locking(lock_fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, IOError):
        print("Another instance is already running. Exiting.")
        sys.exit(0)

def release_lock():
    global lock_fd
    if lock_fd:
        try:
            if platform.system().lower() == 'windows':
                import msvcrt
                msvcrt.locking(lock_fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
            if os.path.exists(LOCK_FILE):
                os.remove(LOCK_FILE)
        except Exception:
            pass
        finally:
            lock_fd = None

def find_binary(name):
    core_path = os.path.join(CORE_DIR, name)
    if platform.system().lower() == 'windows' and not name.endswith('.exe'):
        core_path_exe = core_path + ".exe"
        if os.path.isfile(core_path_exe):
            return core_path_exe
    if os.path.isfile(core_path):
        return core_path
        
    pt_dir = os.path.join(CORE_DIR, "pluggable_transports")
    pt_path = os.path.join(pt_dir, name)
    if platform.system().lower() == 'windows' and not name.endswith('.exe'):
        pt_path_exe = pt_path + ".exe"
        if os.path.isfile(pt_path_exe):
            return pt_path_exe
    if os.path.isfile(pt_path):
        return pt_path
        
    path = shutil.which(name)
    return path if path else None

XRAY_BINARY_PATH = find_binary("xray")
HYSTERIA_BINARY_PATH = find_binary("hysteria")
TOR_BINARY_PATH = find_binary("tor")
SF_PATH = find_binary("snowflake-client")
LYREBIRD_PATH = find_binary("lyrebird")
SNOWFLAKE_BINARY_PATH = SF_PATH or LYREBIRD_PATH
TUIC_BINARY_PATH = find_binary("tuic")
NAIVE_BINARY_PATH = find_binary("naive")
PSIPHON_BINARY_PATH = find_binary("psiphon-tunnel-core")
DNTT_BINARY_PATH = find_binary("dnstt-client")

UNIFIED_CONFIG_FILE = os.path.join(DATA_DIR, "cnfg.json")
SUB_CACHE_FILE = os.path.join(DATA_DIR, "my_configs.config")
WORKING_CONFIGS_CACHE = os.path.join(DATA_DIR, "working_configs.cache")
REPORT_FILE = os.path.join(DATA_DIR, "network_report.json")
STATE_FILE = os.path.join(DATA_DIR, "state.json")

CONFIG = {
    "intervals": {"test_loop": 120, "blackout_loop": 300, "tcp_timeout": 7, "dns_timeout": 5, "http_timeout": 10, "global_test_timeout": 45},
    "targets": {
        "external_ips": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
        "internal_ips": ["217.218.127.127", "217.218.155.155"],
        "portquiz_ip": "193.32.161.165",
        "cf_ip": "104.16.123.96",
        "google_ip": "142.250.190.46",
        "national_speed_urls": ["https://speedtest.rahkasam.ir/5MB.bin"],
        "international_speed_urls": ["https://speed.cloudflare.com/__down?bytes=5000000", "https://speed.hetzner.de/5MB.bin", "https://cachefly.cachefly.net/5mb.test"],
        "doh_endpoints": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"],
        "captive_portal_url": "http://detectportal.firefox.com/canonical.html",
        "ipv6_target": "2606:4700:4700::1111",
        "dns_candidates": ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "9.9.9.10", "94.140.14.14", "94.140.15.15", "217.218.127.127", "217.218.155.155", "91.92.255.244"]
    },
    "thresholds": {"speed_kbps_severe": 20, "speed_kbps_slow": 500, "speed_test_samples": 3, "speed_test_bytes": 2000000, "speed_test_max_duration": 5},

    "cdn_ranges": {
        "cloudflare": [(104,16), (172,64), (162,159), (104,17), (104,18)],
        "gcore": [(92,223), (185,188), (45,133)],
        "aws": ["18.160.0.1", "13.224.0.1", "99.84.0.1"]
    }
}

class Colors:
    HEADER = '\033[95m'; OKBLUE = '\033[94m'; OKCYAN = '\033[96m'; OKGREEN = '\033[92m'; WARNING = '\033[93m'; FAIL = '\033[91m'; ENDC = '\033[0m'; BOLD = '\033[1m'

def log(msg, type="INFO", color_override=None):
    color = color_override if color_override else Colors.ENDC
    if type == "HEADER": color = Colors.HEADER
    elif type == "PASS": color = Colors.OKGREEN
    elif type == "WARN": color = Colors.WARNING
    elif type in ("FAIL", "ERROR"): color = Colors.FAIL
    elif type == "SOL": color = Colors.OKCYAN
    print(f"{color}[{time.strftime('%H:%M:%S')}] [{type}] {msg}{Colors.ENDC}")
    logger.info(f"[{type}] {msg}")

def setup_dynamic_ports():
    global LOCAL_SOCKS_PORT, LOCAL_HTTP_PORT
    release_reserved_ports()
    
    def reserve_port():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        s.listen(1)
        _port_sockets.append(s)
        return s.getsockname()[1]
    
    LOCAL_SOCKS_PORT = reserve_port()
    LOCAL_HTTP_PORT = reserve_port()
    log(f"Allocated and reserved dynamic ports -> SOCKS: {LOCAL_SOCKS_PORT}, HTTP: {LOCAL_HTTP_PORT}", "INFO")

def release_reserved_ports():
    for s in _port_sockets:
        try:
            s.close()
        except Exception:
            pass
    _port_sockets.clear()

def check_dependencies():
    required = ["xray", "hysteria", "tor", "tuic", "naive"]
    missing = [n for n in required if not find_binary(n)]
    
    if missing:
        log(f"Warning: The following core binaries are missing: {', '.join(missing)}", "WARN")
        
    if not SNOWFLAKE_BINARY_PATH:
        log("Warning: Pluggable transports (snowflake-client/lyrebird) are missing.", "WARN")
        
    if not PSIPHON_BINARY_PATH:
        log("Warning: Psiphon binary is missing.", "WARN")
        
    if not DNTT_BINARY_PATH:
        log("Warning: Dnstt-client binary is missing.", "WARN")
        
    if not missing and SNOWFLAKE_BINARY_PATH:
        log("All dependencies are present.", "PASS")

def kill_stale_processes():
    log("Skipping global stale proxy processes cleanup to prevent killing other instances.", "SOL")

def atomic_write_json(filepath, data):
    tmp_path = filepath + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        os.replace(tmp_path, filepath)
        try:
            os.chmod(filepath, 0o600)
        except Exception:
            pass
    except Exception as e:
        log(f"Failed to write {filepath}: {e}", "ERROR")

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"State load error: {e}")
            return {}
    return {}

def save_state(state):
    atomic_write_json(STATE_FILE, state)

def cleanup_child_processes():
    global xray_proc, dnstt_proc
    if dnstt_proc and dnstt_proc.returncode is None:
        try:
            dnstt_proc.terminate()
            time.sleep(0.5)
            if dnstt_proc.returncode is None:
                dnstt_proc.kill()
        except Exception:
            pass
        finally:
            dnstt_proc = None

    if xray_proc and xray_proc.returncode is None:
        try:
            xray_proc.terminate()
            time.sleep(0.5)
            if xray_proc.returncode is None:
                xray_proc.kill()
        except Exception as e:
            log(f"Error during process cleanup: {e}", "WARN")
        finally:
            xray_proc = None

    try:
        state = load_state()
        if state.get('dns_changed'):
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(restore_system_dns())
                loop.close()
            except Exception as e:
                logger.error(f"DNS restore in cleanup failed: {e}")
        if state.get('proxy_backed_up'):
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(restore_system_proxy())
                loop.close()
            except Exception as e:
                logger.error(f"Proxy restore in cleanup failed: {e}")
    except Exception as e:
        logger.error(f"State load error in cleanup: {e}")

    release_reserved_ports()
    release_lock()

atexit.register(cleanup_child_processes)

def setup_signal_handlers():
    loop = asyncio.get_event_loop()
    def handler():
        log("Received termination signal, cleaning up...", "WARN")
        cleanup_child_processes()
        sys.exit(0)
    for sig in [signal.SIGINT, signal.SIGTERM]:
        try:
            loop.add_signal_handler(sig, handler)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda s, f: handler())

async def ensure_geo_files():
    geoip_path = os.path.join(DATA_DIR, "geoip.dat")
    geosite_path = os.path.join(DATA_DIR, "geosite.dat")
    
    needs_download = False
    if not os.path.exists(geoip_path) or os.path.getsize(geoip_path) < 1000000: needs_download = True
    if not os.path.exists(geosite_path) or os.path.getsize(geosite_path) < 1000000: needs_download = True

    if needs_download:
        log("Downloading/Updating GeoIP and GeoSite files for Xray routing...", "SOL")
        resolver = get_resolver(nameservers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        connector = aiohttp.TCPConnector(resolver=resolver, force_close=True, enable_cleanup_closed=True)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60), connector=connector) as session:
            urls = {
                geoip_path: ["https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat", "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"],
                geosite_path: ["https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat", "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"]
            }
            for path, url_list in urls.items():
                if not os.path.exists(path) or os.path.getsize(path) < 1000000:
                    for url in url_list:
                        try:
                            async with session.get(url) as resp:
                                if resp.status == 200:
                                    data = await resp.read()
                                    if len(data) > 1000000:
                                        tmp_path = path + ".tmp"
                                        with open(tmp_path, 'wb') as f:
                                            f.write(data)
                                        os.replace(tmp_path, path)
                                        log(f"  -> Saved {os.path.basename(path)}", "PASS")
                                        break
                        except Exception as e:
                            log(f"Failed to download {os.path.basename(path)} from {url}: {e}.", "WARN")

def create_background_task(coro):
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task

async def fetch_fresh_configs(wait=True):
    original_cwd = os.getcwd()
    try:
        os.chdir(DATA_DIR)
        sys.path.insert(0, CORE_DIR)
        import cnfg
        log("Running cnfg as module...", "SOL")
        if hasattr(cnfg, 'main'):
            old_mtime = os.path.getmtime(UNIFIED_CONFIG_FILE) if os.path.exists(UNIFIED_CONFIG_FILE) else 0
            if inspect.iscoroutinefunction(cnfg.main):
                await cnfg.main()
            else:
                await asyncio.get_event_loop().run_in_executor(None, cnfg.main)
            new_mtime = os.path.getmtime(UNIFIED_CONFIG_FILE) if os.path.exists(UNIFIED_CONFIG_FILE) else 0
            if new_mtime > old_mtime:
                log("Fresh configs fetched successfully via module!", "PASS")
                clear_cached_configs()
                return True
            else:
                log("Module ran but no new configs generated.", "WARN")
                return False
    except ImportError:
        pass
    except Exception as e:
        logger.error(f"Module cnfg execution failed: {e}. Falling back to subprocess.")
    finally:
        os.chdir(original_cwd)
        if CORE_DIR in sys.path:
            sys.path.remove(CORE_DIR)

    cnfg_script = os.path.join(CORE_DIR, "cnfg.py")
    cnfg_exe = os.path.join(CORE_DIR, "cnfg.exe")
    
    if os.path.exists(cnfg_exe):
        cmd = [cnfg_exe]
    elif os.path.exists(cnfg_script):
        cmd = [sys.executable, cnfg_script]
    else:
        log("cnfg (cnfg.py/cnfg.exe) not found in Core directory! Cannot auto-fetch.", "FAIL")
        return False

    log("Running cnfg to get fresh configs via subprocess...", "SOL")
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if platform.system().lower() == 'windows' else 0
        old_mtime = os.path.getmtime(UNIFIED_CONFIG_FILE) if os.path.exists(UNIFIED_CONFIG_FILE) else 0
        
        proc = await asyncio.create_subprocess_exec(
            *cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            creationflags=creationflags,
            cwd=DATA_DIR
        )
        
        if wait:
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=45)
            except asyncio.TimeoutError:
                log("cnfg took too long (45s). Terminating.", "WARN")
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    try: proc.kill()
                    except: pass
                except Exception: pass
                return False

            new_mtime = os.path.getmtime(UNIFIED_CONFIG_FILE) if os.path.exists(UNIFIED_CONFIG_FILE) else 0
            if proc.returncode == 0 and new_mtime > old_mtime:
                log("Fresh configs fetched successfully!", "PASS")
                clear_cached_configs()
                return True
            else:
                err = stderr.decode(errors='ignore')
                log(f"cnfg exited with error or no update: {err}", "WARN")
                return False
        else:
            async def bg_task():
                try:
                    await proc.communicate()
                    new_mtime = os.path.getmtime(UNIFIED_CONFIG_FILE) if os.path.exists(UNIFIED_CONFIG_FILE) else 0
                    if proc.returncode == 0 and new_mtime > old_mtime:
                        log("Background cnfg fetch completed successfully.", "PASS")
                        clear_cached_configs()
                    else:
                        log("Background cnfg fetch finished with errors or no update.", "WARN")
                except Exception as e:
                    logger.error(f"Background cnfg fetch failed: {e}")
            create_background_task(bg_task())
            log("Background config fetch started.", "INFO")
            return "started"
    except Exception as e:
        log(f"Failed to run cnfg: {e}", "WARN")
        return False

def load_unified_config():
    if not os.path.exists(UNIFIED_CONFIG_FILE):
        template = {"configs": [], "subscription_urls": [], "warp": None, "cloudflare_worker": None, "psiphon": None, "dnstt": None}
        atomic_write_json(UNIFIED_CONFIG_FILE, template)
        return template
    try:
        with open(UNIFIED_CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data.get("configs"), list): data["configs"] = []
            if not isinstance(data.get("subscription_urls"), list): data["subscription_urls"] = []
            if not isinstance(data.get("warp"), dict): data["warp"] = None
            if not isinstance(data.get("cloudflare_worker"), dict): data["cloudflare_worker"] = None
            if not isinstance(data.get("psiphon"), dict): data["psiphon"] = None
            if not isinstance(data.get("dnstt"), dict): data["dnstt"] = None
            return data
    except Exception as e:
        log(f"Error reading {UNIFIED_CONFIG_FILE}: {e}", "ERROR")
        return {"configs": [], "subscription_urls": [], "warp": None, "cloudflare_worker": None, "psiphon": None, "dnstt": None}

def load_cached_configs():
    if not os.path.exists(SUB_CACHE_FILE): return []
    with open(SUB_CACHE_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f.readlines() if line.strip() and not line.startswith("#")]

def clear_cached_configs():
    if os.path.exists(SUB_CACHE_FILE):
        os.remove(SUB_CACHE_FILE)

def save_working_config(link):
    try:
        existing = load_working_configs()
        if link not in existing:
            existing.append(link)
            if len(existing) > 100:
                existing = existing[-100:]
            with open(WORKING_CONFIGS_CACHE, "w") as f:
                f.write("\n".join(existing) + "\n")
            try:
                os.chmod(WORKING_CONFIGS_CACHE, 0o600)
            except Exception:
                pass
    except Exception as e:
        logger.error(f"Failed to save working config: {e}")

def remove_working_config(link):
    try:
        existing = load_working_configs()
        if link in existing:
            existing.remove(link)
            with open(WORKING_CONFIGS_CACHE, "w") as f:
                f.write("\n".join(existing) + "\n")
    except Exception as e:
        logger.error(f"Failed to remove working config: {e}")

def load_working_configs():
    if not os.path.exists(WORKING_CONFIGS_CACHE): return []
    with open(WORKING_CONFIGS_CACHE, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

async def fetch_subscription_configs(urls):
    all_links = []
    valid_protocols = ["vless", "vmess", "ss", "trojan", "hysteria2", "hy2", "tuic", "naive", "naive+https", "shadowtls"]
    try:
        log(f"Fetching configs from subscription URLs...", "INFO")
        resolver = get_resolver(nameservers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        connector = aiohttp.TCPConnector(resolver=resolver, force_close=True, enable_cleanup_closed=True)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30), headers={"User-Agent": "v2rayN/6.0"}, connector=connector) as session:
            for url in urls:
                for attempt in range(3):
                    try:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                links = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#") and any(line.startswith(p + "://") for p in valid_protocols)]
                                if not links:
                                    try:
                                        decoded = base64.b64decode(text).decode('utf-8')
                                        links = [line.strip() for line in decoded.splitlines() if line.strip() and not line.startswith("#") and any(line.startswith(p + "://") for p in valid_protocols)]
                                    except Exception:
                                        pass
                                if links:
                                    all_links.extend(links)
                                break
                            else:
                                await asyncio.sleep(2 ** attempt)
                    except Exception as e:
                        logger.warning(f"Sub fetch error for {url} (attempt {attempt+1}): {e}")
                        await asyncio.sleep(2 ** attempt)
    except Exception as e:
        logger.error(f"Sub fetch general error: {e}")
    if all_links:
        tmp_path = SUB_CACHE_FILE + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write("\n".join(all_links))
        os.replace(tmp_path, SUB_CACHE_FILE)
        try:
            os.chmod(SUB_CACHE_FILE, 0o600)
        except Exception:
            pass
    else:
        if os.path.exists(SUB_CACHE_FILE):
            os.remove(SUB_CACHE_FILE)
    return all_links

async def prompt_and_fetch_custom_configs():
    log("Do you want to add your custom subscription links? (y/n)", "INFO")
    try:
        choice = input().strip().lower()
        if choice == 'y':
            log("Enter your subscription URL(s) separated by comma:", "INFO")
            urls_input = input().strip()
            if urls_input:
                urls = [u.strip() for u in urls_input.split(',') if u.strip()]
                if urls:
                    unified_cfg = load_unified_config()
                    unified_cfg["subscription_urls"] = urls
                    atomic_write_json(UNIFIED_CONFIG_FILE, unified_cfg)
                    log("Custom links saved. Fetching configs...", "SOL")
                    await fetch_subscription_configs(urls)
    except Exception as e:
        log(f"Input error: {e}", "WARN")

def is_root_or_admin():
    if platform.system().lower() == 'windows':
        try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except: return False
    return hasattr(os, 'geteuid') and os.geteuid() == 0

async def get_default_interface():
    system = platform.system().lower()
    if system == 'windows':
        proc = await asyncio.create_subprocess_exec('powershell', '-Command', 'Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -ExpandProperty InterfaceAlias', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate()
        return stdout.decode().strip().split('\n')[0].strip()
    elif system == 'darwin':
        try:
            route_proc = await asyncio.create_subprocess_exec('route', '-n', 'get', 'default', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await route_proc.communicate()
            output = stdout.decode()
            iface = "en0"
            if "interface:" in output:
                iface = output.split("interface:")[1].split()[0]
            
            svc_proc = await asyncio.create_subprocess_exec('networksetup', '-listallhardwareports', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await svc_proc.communicate()
            lines = stdout.decode().splitlines()
            
            current_hw = None
            for line in lines:
                if "Hardware Port:" in line:
                    current_hw = line.replace("Hardware Port: ", "").strip()
                elif "Device: " + iface in line:
                    return current_hw
            return "Wi-Fi"
        except Exception:
            return "Wi-Fi"
    else:
        proc = await asyncio.create_subprocess_exec('ip', 'route', 'show', 'default', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate()
        output = stdout.decode().strip()
        return output.split("dev")[1].split()[0] if "dev" in output else "eth0"

def extract_dns_ips(text):
    ips = []
    for line in text.splitlines():
        if "DNS Servers" in line or "Statically Configured DNS" in line or "Dynamically Configured DNS" in line:
            for token in re.findall(r'[^\s,;]+', line):
                try:
                    ipaddress.ip_address(token)
                    ips.append(token)
                except ValueError:
                    pass
    if not ips:
        for token in re.findall(r'[^\s,;]+', text):
            try:
                ipaddress.ip_address(token)
                ips.append(token)
            except ValueError:
                pass
    return ips

async def send_dns_query(ip, domain):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    txid = random.randint(0, 65535)
    packet = txid.to_bytes(2, 'big') + (0x0100).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (0).to_bytes(6, 'big')
    qname = b''.join([len(part).to_bytes(1, 'big') + part.encode() for part in domain.split('.')]) + b'\x00'
    packet += qname + (1).to_bytes(2, 'big') + (1).to_bytes(2, 'big')
    try:
        await loop.sock_sendto(sock, packet, (ip, 53))
        data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), timeout=CONFIG["intervals"]["dns_timeout"])
        if len(data) < 12: return None
        flags = int.from_bytes(data[2:4], 'big')
        if not (flags & 0x8000): return None
        rcode = flags & 0xF
        ancount = int.from_bytes(data[6:8], 'big')
        resp_txid = int.from_bytes(data[:2], 'big')
        return {'rcode': rcode, 'ancount': ancount, 'txid': resp_txid, 'expected_txid': txid}
    except asyncio.TimeoutError:
        return None
    except Exception as e:
        logger.debug(f"DNS query error: {e}")
        return None
    finally: sock.close()

async def scan_fastest_dns():
    log("Scanning for fastest and cleanest DNS servers...", "SOL")
    candidates = CONFIG["targets"]["dns_candidates"]
    
    async def test_dns(ip):
        start = time.time()
        res = await send_dns_query(ip, "example.com")
        if res is None or res.get('rcode', 1) != 0 or res.get('ancount', 0) == 0:
            return None

        rand_res = await send_dns_query(ip, ''.join(random.choices(string.ascii_lowercase, k=10)) + ".com")
        if rand_res is not None and rand_res.get('ancount', 0) > 0:
            return None
        latency = round((time.time() - start) * 1000, 2)
        return (ip, latency)
        
    results = await asyncio.gather(*[test_dns(ip) for ip in candidates], return_exceptions=True)
    valid = [r for r in results if r and not isinstance(r, Exception)]
    valid.sort(key=lambda x: x[1])
    
    if valid:
        top_ips = [ip for ip, lat in valid[:3]]
        log(f"  -> Fastest DNS: {', '.join(top_ips)}", "PASS")
        return top_ips
    return ["1.1.1.1", "8.8.8.8"]

async def test_doh_resolution():
    log("  -> Testing DoH (DNS over HTTPS)...", "INFO")
    results = []
    for doh_url in CONFIG["targets"]["doh_endpoints"]:
        try:
            txid = random.randint(0, 65535)
            qname = b''.join([len(part).to_bytes(1, 'big') + part.encode() for part in "example.com".split('.')]) + b'\x00'
            packet = txid.to_bytes(2, 'big') + (0x0100).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (0).to_bytes(6, 'big')
            packet += qname + (1).to_bytes(2, 'big') + (1).to_bytes(2, 'big')
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.post(doh_url, data=packet, headers={"Content-Type": "application/dns-message"}) as resp:
                    if resp.status == 200:
                        data = await resp.read()
                        if len(data) >= 12:
                            flags = int.from_bytes(data[2:4], 'big')
                            if not (flags & 0x8000):
                                results.append('unknown')
                                continue
                            resp_txid = int.from_bytes(data[:2], 'big')
                            rcode = flags & 0xF
                            ancount = int.from_bytes(data[6:8], 'big')
                            if resp_txid == txid and rcode == 0 and ancount > 0:
                                results.append('ok')
                            else:
                                results.append('unknown')
                        else:
                            results.append('unknown')
                    else:
                        results.append('dropped')
        except asyncio.TimeoutError:
            results.append('dropped')
        except Exception as e:
            logger.debug(f"DoH error: {e}")
            results.append('unknown')

    if not results: return 'unknown'
    if 'ok' in results: return 'ok'
    if all(r == 'dropped' for r in results): return 'dropped'
    return 'unknown'

async def check_direct_health():
    log("Running strict direct health check (HTTPS & Anti-Blockpage)...", "INFO")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"}
    try:
        resolver = get_resolver(nameservers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        connector = aiohttp.TCPConnector(force_close=True, enable_cleanup_closed=True, resolver=resolver)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), headers=headers, trust_env=False, connector=connector) as session:
            checks_passed = 0
            checks_total = 0

            checks_total += 1
            try:
                async with session.get("https://www.google.com/generate_204", allow_redirects=False) as resp:
                    body = await resp.read()
                    location = resp.headers.get("Location", "")
                    if resp.status in (200, 204) and len(body) == 0:
                        checks_passed += 1
                    elif resp.status in (301, 302) and ("consent.google.com" in location or "www.google.com" in location):
                        checks_passed += 1
                    elif "10.10.34.34" in location or resp.status in (403, 451):
                        log("  -> Google generate_204: BLOCKED", "WARN")
                    else:
                        log(f"  -> Google generate_204: Unexpected status {resp.status}", "WARN")
            except Exception as e:
                log(f"  -> Google generate_204: Failed ({type(e).__name__})", "WARN")

            checks_total += 1
            try:
                async with session.get("https://www.youtube.com/generate_204", allow_redirects=False) as resp:
                    body = await resp.read()
                    location = resp.headers.get("Location", "")
                    if resp.status in (200, 204) and len(body) == 0:
                        checks_passed += 1
                    elif resp.status in (301, 302) and ("consent.google.com" in location or "www.google.com" in location):
                        checks_passed += 1
                    elif "10.10.34.34" in location or resp.status in (403, 451):
                        log("  -> YouTube generate_204: BLOCKED", "WARN")
                    else:
                        log(f"  -> YouTube generate_204: Unexpected status {resp.status}", "WARN")
            except Exception as e:
                log(f"  -> YouTube generate_204: Failed ({type(e).__name__})", "WARN")

            checks_total += 1
            try:
                async with session.get("https://1.1.1.1/cdn-cgi/trace") as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if "ip=" in text:
                            checks_passed += 1
            except Exception as e:
                log(f"  -> Cloudflare trace: Failed ({type(e).__name__})", "WARN")

            if checks_passed >= 2:
                log(f"  -> Direct health check: PASSED ({checks_passed}/{checks_total})", "PASS")
                return True
            else:
                log(f"  -> Direct health check: FAILED ({checks_passed}/{checks_total})", "WARN")
                return False
    except Exception as e:
        logger.error(f"Direct health check session error: {e}")
    return False

async def check_geolocation():
    resolver = get_resolver(nameservers=["1.1.1.1", "8.8.8.8"])
    try:
        timeout = aiohttp.ClientTimeout(total=8)
        connector = aiohttp.TCPConnector(resolver=resolver)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            country = 'Unknown'
            
            try:
                async with session.get("https://ipinfo.io/json") as resp:
                    data = await resp.json()
                    country = data.get('country', 'Unknown')
            except Exception as e:
                logger.debug(f"ipinfo.io failed: {e}")

            if country == 'Unknown':
                try:
                    async with session.get("https://api.country.is/") as resp:
                        data = await resp.json()
                        country = data.get('country', 'Unknown')
                except Exception as e:
                    logger.debug(f"api.country.is failed: {e}")

            if country == 'IR':
                log(f"Geolocation: {country}. Inside Iran network.", "WARN")
                return True
            elif country != 'Unknown':
                log(f"Geolocation: {country}. Already bypassing or outside Iran.", "PASS")
                return False
            else:
                log("Geolocation undetermined. Assuming inside Iran to run tests.", "WARN")
                return True
    except Exception as e:
        log(f"Geolocation check failed ({e}). Assuming inside Iran.", "WARN")
        return True

async def test_icmp(ip):
    system = platform.system().lower()
    cmd = ['ping', '-n', '1', '-w', '2000', ip] if system == 'windows' else ['ping', '-c', '1', '-W', '2', ip]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        await asyncio.wait_for(proc.communicate(), timeout=3)
        return proc.returncode == 0
    except Exception as e:
        logger.debug(f"ICMP error: {e}")
        return False

async def get_icmp_latency(ip):
    system = platform.system().lower()
    cmd = ['ping', '-n', '1', '-w', '2000', ip] if system == 'windows' else ['ping', '-c', '1', '-W', '2', ip]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
        if proc.returncode == 0:
            output = stdout.decode(errors='ignore')
            match = re.search(r'(?:time|زمان)\s*[=<]\s*(\d+\.?\d*)\s*ms', output)
            if match:
                return float(match.group(1))
        return None
    except Exception as e:
        logger.debug(f"ICMP latency error: {e}")
        return None

async def test_tcp_ping(ip, port=443):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=CONFIG["intervals"]["tcp_timeout"])
        writer.close()
        await writer.wait_closed()
        return True
    except Exception as e:
        logger.debug(f"TCP ping error to {ip}:{port}: {e}")
        return False

async def test_ip_layer():
    log("Phase 1: Checking Network & Routing Layer...", "HEADER")
    state = {'internal': False, 'external': False, 'icmp': False, 'tcp_ping': False, 'ipv6': 'unknown'}
    async def check_tcp(ip, port):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=CONFIG["intervals"]["tcp_timeout"])
            writer.close(); await writer.wait_closed(); return True
        except Exception: return False

    tcp_ext_tasks_443 = [test_tcp_ping(ip, 443) for ip in CONFIG["targets"]["external_ips"]]
    tcp_ext_tasks_80 = [test_tcp_ping(ip, 80) for ip in CONFIG["targets"]["external_ips"]]
    tcp_ext_results = await asyncio.gather(*(tcp_ext_tasks_443 + tcp_ext_tasks_80))
    state['tcp_ping'] = any(tcp_ext_results)

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(CONFIG["targets"]["ipv6_target"], 443), timeout=2)
        writer.close(); await writer.wait_closed()
        state['ipv6'] = 'ok'
    except Exception as e:
        logger.debug(f"IPv6 error: {e}")
        state['ipv6'] = 'dropped'

    icmp_ext_tasks = [test_icmp(ip) for ip in CONFIG["targets"]["external_ips"]]
    icmp_int_tasks = [test_icmp(ip) for ip in CONFIG["targets"]["internal_ips"]]
    icmp_ext, icmp_int = await asyncio.gather(asyncio.gather(*icmp_ext_tasks), asyncio.gather(*icmp_int_tasks))
    
    has_icmp_ext = any(icmp_ext)
    has_icmp_int = any(icmp_int)
    state['icmp'] = has_icmp_ext or has_icmp_int

    ext_tcp_tasks = [check_tcp(ip, 443) for ip in CONFIG["targets"]["external_ips"]]
    ext_tcp_results = await asyncio.gather(*ext_tcp_tasks)
    
    state['external'] = state['tcp_ping'] or has_icmp_ext or any(ext_tcp_results)
    
    internal_tasks = [check_tcp(ip, 53) for ip in CONFIG["targets"]["internal_ips"]]
    int_tcp_results = await asyncio.gather(*internal_tasks)
    state['internal'] = has_icmp_int or any(int_tcp_results)
    
    return state

async def test_dns_layer():
    log("Phase 2: Checking DNS Layer (Hijack Detection via Local vs DoH)...", "HEADER")
    
    loop = asyncio.get_running_loop()
    system_dns_ok = False
    try:
        await loop.getaddrinfo('www.google.com', 443)
        system_dns_ok = True
    except Exception:
        system_dns_ok = False

    if not system_dns_ok:
        log("  -> System DNS cannot resolve www.google.com!", "WARN")

    dns_ip = random.choice(CONFIG["targets"]["external_ips"])
    
    res = await send_dns_query(dns_ip, 'example.com')
    if res is None:
        udp_status = 'dropped'
    elif res.get('txid') != res.get('expected_txid'):
        udp_status = 'unknown'
    elif res['rcode'] != 0 and res['ancount'] == 0:
        udp_status = 'unknown'
    else:
        udp_status = 'ok'

    doh_res = await test_doh_resolution()
    local_res_ips = None
    
    rand_domain = ''.join(random.choices(string.ascii_lowercase, k=10)) + ".com"
    try:
        local_res_ips = await loop.getaddrinfo(rand_domain, None)
    except socket.gaierror:
        pass
    except Exception as e:
        logger.error(f"Unexpected DNS resolution error: {e}")

    if local_res_ips:
        public_found = False
        for fam, _, _, _, sockaddr in local_res_ips:
            ip = sockaddr[0]
            if ip.startswith('10.') or ip.startswith('172.') or ip.startswith('192.168.') or ip == '127.0.0.1':
                continue
            public_found = True
        if public_found:
            return 'hijacked'

    if not system_dns_ok:
        if udp_status == 'ok' or doh_res == 'ok':
            log("  -> System DNS broken but direct DNS works. Needs fix.", "WARN")
            return 'system_broken'

    if udp_status == 'dropped' and doh_res == 'ok': return 'doh_only'
    if udp_status == 'dropped' and doh_res == 'dropped': return 'dropped'
    return 'ok'

async def test_vpn_ports():
    log("Phase 3: Checking VPN Ports...", "HEADER")

    portquiz_reachable = False
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(CONFIG["targets"]["portquiz_ip"], 443), timeout=5)
        writer.close(); await writer.wait_closed()
        portquiz_reachable = True
    except:
        pass

    if not portquiz_reachable:
        log("  -> portquiz.net is unreachable. Port test skipped.", "WARN")
        return 'unknown'

    async def check_port(port):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(CONFIG["targets"]["portquiz_ip"], port), timeout=5)
            writer.close(); await writer.wait_closed(); return port, True
        except asyncio.TimeoutError: return port, 'timeout'
        except Exception as e:
            logger.debug(f"Port check error: {e}")
            return port, False
    results = await asyncio.gather(*[check_port(p) for p in [1194, 1701, 1723, 443, 80]])
    blocked = [p for p, res in results if res is False]
    timed_out = [p for p, res in results if res == 'timeout']
    if len(blocked) + len(timed_out) == 5: return 'blocked'
    elif blocked: return 'partial'
    return 'ok'

async def test_udp_status():
    results = []
    for ip in CONFIG["targets"]["external_ips"]:
        res = await send_dns_query(ip, 'example.com')
        if res is not None and res.get('ancount', 0) > 0 and res.get('txid') == res.get('expected_txid'):
            results.append('ok')
        elif res is None:
            results.append('dropped')
        else:
            results.append('unknown')

    if 'ok' in results:
        return 'ok'
    if all(r == 'dropped' for r in results):
        return 'dropped'
    return 'unknown'

def _sync_test_warp_udp(test_endpoints):
    reachable = 0
    wg_packet = b'\x01\x00\x00\x00'
    
    for ip, port in test_endpoints:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(wg_packet, (ip, port))
            try:
                data, _ = sock.recvfrom(1024)
                if len(data) > 0:
                    reachable += 1
            except socket.timeout:
                pass
            except ConnectionRefusedError:
                pass
            sock.close()
        except Exception:
            pass
    if reachable >= 2: return 'ok'
    elif reachable >= 1: return 'partial'
    return 'dropped'

async def test_warp_udp_reachability():
    test_endpoints = [
        ("162.159.192.1", 2408), ("162.159.193.1", 2408), ("188.114.96.1", 2408),
        ("162.159.192.1", 4500), ("162.159.193.1", 500)
    ]
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _sync_test_warp_udp, test_endpoints)
    
def _sync_scan_udp_reachability(test_endpoints):
    working = []
    wg_packet = b'\x01\x00\x00\x00'
    for ip, port in test_endpoints:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.5)
            sock.sendto(wg_packet, (ip, port))
            try:
                data, _ = sock.recvfrom(1024)
                if data: working.append((ip, port))
            except socket.timeout:
                pass
            finally:
                sock.close()
        except Exception:
            pass
    return list(set(working))

async def scan_udp_reachability():
    log("Scanning for UDP reachable WARP endpoints (Heuristic Probe)...", "SOL")
    test_endpoints = [
        ("162.159.192.1", 2408), ("162.159.193.1", 2408),
        ("188.114.96.1", 2408), ("162.159.192.1", 4500),
        ("162.159.192.1", 500), ("188.114.96.1", 500)
    ]
    loop = asyncio.get_running_loop()
    working_endpoints = await loop.run_in_executor(None, _sync_scan_udp_reachability, test_endpoints)
    if not working_endpoints:
        log("  -> No reachable WARP UDP endpoint found.", "WARN")
    return working_endpoints

def _sync_test_udp_443_probe(target_ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        packet = b'\xc0\x00\x00\x00\x01\x08' + b'\x12\x34\x56\x78\x9a\xbc\xde\xf0' + b'\x00\x00\x00\x29\x00\x00\x00\x01\x06\x00\x05\x00\x00\x00\x00\x00'
        sock.sendto(packet, (target_ip, 443))
        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            return 'reachable' if len(data) > 0 else 'unknown'
        except socket.timeout:
            sock.close()
            return 'unknown'
        except ConnectionRefusedError:
            sock.close()
            return 'dropped'
    except Exception as e:
        return 'unknown'

async def test_udp_443_probe():
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _sync_test_udp_443_probe, CONFIG["targets"]["google_ip"])

async def scan_clean_cdn_ips(cdn_provider="cloudflare", worker_host=None, worker_path="/", count=3):
    log(f"Scanning for clean {cdn_provider.capitalize()} IPs...", "SOL")
    
    def get_random_ip():
        if cdn_provider == "cloudflare":
            choice = random.choice(CONFIG["cdn_ranges"]["cloudflare"])
            return f"{choice[0]}.{choice[1]}.{random.randint(0,255)}.{random.randint(0,255)}"
        elif cdn_provider == "gcore":
            choice = random.choice(CONFIG["cdn_ranges"]["gcore"])
            return f"{choice[0]}.{choice[1]}.{random.randint(0,255)}.{random.randint(0,255)}"
        elif cdn_provider == "aws":
            return random.choice(CONFIG["cdn_ranges"]["aws"])
        return "1.1.1.1"
    
    async def test_ip(ip):
        try:
            start = time.time()
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 443), timeout=2)
            latency = round((time.time() - start) * 1000, 2)
            writer.close()
            await writer.wait_closed()
            
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ssl_reader, ssl_writer = await asyncio.open_connection(host=ip, port=443, ssl=ctx, server_hostname=worker_host or 'speed.cloudflare.com')
            
            req = f"GET {worker_path} HTTP/1.1\r\nHost: {worker_host or 'speed.cloudflare.com'}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            ssl_writer.write(req.encode())
            await ssl_writer.drain()
            resp_data = await ssl_reader.read(1024)
            ssl_writer.close()
            await ssl_writer.wait_closed()
            
            if b"HTTP/1.1 101" in resp_data or b"HTTP/1.1 426" in resp_data or b"HTTP/1.1 400" in resp_data:
                return (ip, latency)
            return None
        except Exception:
            return None
    
    tasks = [test_ip(get_random_ip()) for _ in range(count * 5)]
    results = await asyncio.gather(*tasks)
    working_ips = [r for r in results if r is not None]
    working_ips.sort(key=lambda x: x[1])
    
    if working_ips:
        return [ip for ip, lat in working_ips[:count]]
    else:
        log(f"  -> No clean {cdn_provider} IP found in scan.", "WARN")
        return []

async def resolve_via_doh(domain):
    doh_servers = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"]
    for doh in doh_servers:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.get(
                    f"{doh}?name={domain}&type=A",
                    headers={"accept": "application/dns-json"}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for answer in data.get("Answer", []):
                            if answer.get("type") == 1:
                                return answer["data"]
        except Exception as e:
            logger.debug(f"DoH resolve error on {doh} for {domain}: {e}")
    return None


async def test_dpi_layer():
    log("Phase 4: Checking Deep Packet Inspection (Behavioral & SNI)...", "HEADER")
    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"}
    targets = {
        "youtube": "https://www.youtube.com/generate_204",
        "google": "https://www.google.com/generate_204"
    }
    
    results = {}
    resolver = get_resolver(nameservers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    connector = aiohttp.TCPConnector(force_close=True, enable_cleanup_closed=True, resolver=resolver)
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), headers=headers, trust_env=False, connector=connector) as session:
        for name, url in targets.items():
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    body = await resp.read()
                    loc = resp.headers.get("Location", "")
                    
                    if name == "youtube":
                        log(f"  -> YouTube DPI: Status={resp.status}, Loc={loc}", "INFO")
                        if resp.status in (200, 204) and len(body) == 0:
                            results[name] = 'ok'
                        elif resp.status in (301, 302) and ("consent.google.com" in loc or "www.google.com" in loc):
                            results[name] = 'ok'
                        elif "10.10.34.34" in loc or (b'filter' in body.lower() and b'blocked' in body.lower()):
                            results[name] = 'blocked'
                        else:
                            results[name] = 'unknown'
                    elif name == "google":
                        log(f"  -> Google DPI: Status={resp.status}, Loc={loc}", "INFO")
                        if resp.status in (200, 204) and len(body) == 0:
                            results[name] = 'ok'
                        elif resp.status in (301, 302) and "consent.google.com" in loc:
                            results[name] = 'ok'
                        else:
                            results[name] = 'unknown'
            except asyncio.TimeoutError:
                log(f"  -> {name} DPI Test: Timeout", "WARN")
                results[name] = 'timeout'
            except aiohttp.ClientConnectorError as e:
                log(f"  -> {name} DPI Test: Connection Error: {e}", "WARN")
                results[name] = 'unknown'
            except Exception as e:
                logger.debug(f"DPI test error for {url}: {e}")
                results[name] = 'unknown'
                
    ggl_res = results.get("google")
    yt_res = results.get("youtube")
    
    if ggl_res == 'ok':
        if yt_res == 'blocked':
            return 'rst'
        elif yt_res == 'ok':
            return 'none'
        return 'unknown'
        
    if ggl_res in ('blocked', 'unknown', 'timeout') and yt_res in ('blocked', 'unknown', 'timeout'):
        return 'aggressive'
        
    return 'unknown'

async def test_throttling():
    log("Phase 5: Checking Bandwidth...", "HEADER")
    
    resolver = get_resolver(nameservers=["1.1.1.1", "8.8.8.8"])
    connector = aiohttp.TCPConnector(resolver=resolver, limit=5)

    async def download_test(url, session):
        async with speed_test_sem:
            try:
                start = time.time(); downloaded = 0
                async with session.get(url) as response:
                    response.raise_for_status()
                    async for chunk in response.content.iter_chunked(8192):
                        downloaded += len(chunk)
                        if downloaded >= CONFIG["thresholds"]["speed_test_bytes"] or (time.time() - start) >= CONFIG["thresholds"]["speed_test_max_duration"]: break
                return (downloaded * 8 / 1000) / (time.time() - start) if downloaded > 0 else 0
            except Exception as e:
                logger.debug(f"Download test error on {url}: {e}")
                return 0

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=CONFIG["intervals"]["http_timeout"]), connector=connector) as session:
        nat_speeds = await asyncio.gather(*[download_test(nat_url, session) for nat_url in CONFIG["targets"]["national_speed_urls"] for _ in range(CONFIG["thresholds"]["speed_test_samples"])])
        int_speeds = await asyncio.gather(*[download_test(int_url, session) for int_url in CONFIG["targets"]["international_speed_urls"] for _ in range(CONFIG["thresholds"]["speed_test_samples"])])
        
        nat_speed = statistics.median([s for s in nat_speeds if s > 0]) if any(nat_speeds) else 0
        int_speed = statistics.median([s for s in int_speeds if s > 0]) if any(int_speeds) else 0
        
        if int_speed == 0 and nat_speed > 0: return 'intl_cut'
        if int_speed == 0 and nat_speed == 0: return 'failed'
        if int_speed < CONFIG["thresholds"]["speed_kbps_severe"] and nat_speed > int_speed * 3: return 'throttled_intl'
        elif int_speed < CONFIG["thresholds"]["speed_kbps_slow"]: return 'slow'
        return 'ok'

async def get_current_dns():
    system = platform.system().lower()
    interface = await get_default_interface()
    try:
        if system == 'windows':
            v4_out = ""
            v6_out = ""
            try:
                p1 = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'show', 'dns', f'name="{interface}"', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, _ = await p1.communicate()
                v4_out = stdout.decode()
            except: pass
            try:
                p2 = await asyncio.create_subprocess_exec('netsh', 'interface', 'ipv6', 'show', 'dns', f'name="{interface}"', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, _ = await p2.communicate()
                v6_out = stdout.decode()
            except: pass

            v4_ips = extract_dns_ips(v4_out)
            v6_ips = extract_dns_ips(v6_out)
            v4_is_dhcp = "DHCP" in v4_out
            v6_is_dhcp = "DHCP" in v6_out
            
            return json.dumps({
                "v4_mode": "DHCP" if v4_is_dhcp else "STATIC",
                "v4_servers": v4_ips,
                "v6_mode": "DHCP" if v6_is_dhcp else "STATIC",
                "v6_servers": v6_ips
            })
        elif system == 'darwin':
            proc = await asyncio.create_subprocess_exec('networksetup', '-getdnsservers', interface, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await proc.communicate()
            out = stdout.decode().strip()
            return out if out else "EMPTY"
        else:
            if shutil.which('resolvectl'):
                proc = await asyncio.create_subprocess_exec('resolvectl', 'dns', interface, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, _ = await proc.communicate()
                out = stdout.decode().strip()
                ips = extract_dns_ips(out)
                return " ".join(ips) if ips else "EMPTY"
            return "EMPTY"
    except Exception:
        return "EMPTY"

async def apply_system_dns():
    if not is_root_or_admin(): return False
    interface = await get_default_interface()
    if not interface: return False
    system = platform.system().lower()
    state = load_state()
    
    if not state.get('dns_backed_up'):
        state['original_dns'] = await get_current_dns()
        state['dns_backed_up'] = True
        
    state['dns_changed'] = True
    state['interface'] = interface
    save_state(state)
    
    try:
        best_dns_list = await scan_fastest_dns()
        if not best_dns_list:
            best_dns_list = ["1.1.1.1", "8.8.8.8"]
            
        primary_dns = best_dns_list[0]
        secondary_dns = best_dns_list[1] if len(best_dns_list) > 1 else primary_dns
        primary_v6 = "2606:4700:4700::1111"
        
        if system == 'windows':
            p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'set', 'dns', f'name="{interface}"', 'static', primary_dns, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await p.communicate()
            if p.returncode != 0:
                await restore_system_dns()
                return False
                
            p_add = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'add', 'dns', f'name="{interface}"', secondary_dns, 'index=2', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await p_add.communicate()
                
            p6 = await asyncio.create_subprocess_exec('netsh', 'interface', 'ipv6', 'set', 'dns', f'name="{interface}"', 'static', primary_v6, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await p6.communicate()
            
            p_flush = await asyncio.create_subprocess_exec('ipconfig', '/flushdns', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await p_flush.communicate()
        elif system == 'darwin':
            p = await asyncio.create_subprocess_exec('networksetup', '-setdnsservers', interface, primary_dns, secondary_dns, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await p.communicate()
            if p.returncode != 0:
                await restore_system_dns()
                return False
        else:
            if shutil.which('resolvectl'):
                p = await asyncio.create_subprocess_exec('resolvectl', 'dns', interface, primary_dns, secondary_dns, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0:
                    await restore_system_dns()
                    return False
            else:
                await restore_system_dns()
                return False
        return True
    except Exception as e:
        logger.error(f"Failed to apply system DNS: {e}")
        await restore_system_dns()
        return False

async def restore_system_dns():
    state = load_state()
    if not state.get('dns_changed'): 
        return True
        
    interface = state.get('interface')
    if not interface:
        interface = await get_default_interface()
        
    if not interface:
        log("Cannot determine network interface to restore DNS.", "WARN")
        return False
        
    original_dns = state.get('original_dns', "")
    system = platform.system().lower()
    try:
        if system == 'windows':
            try:
                dns_data = json.loads(original_dns)
            except:
                dns_data = {
                    "v4_mode": "DHCP", 
                    "v4_servers": [], 
                    "v6_mode": "DHCP", 
                    "v6_servers": []
                }
                
            if dns_data.get("v4_mode") == "DHCP":
                p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'set', 'dns', f'name="{interface}"', 'source=dhcp', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0: return False
            else:
                v4_ips = dns_data.get("v4_servers", [])
                if v4_ips:
                    p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'set', 'dns', f'name="{interface}"', 'static', v4_ips[0], 'primary', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    await p.communicate()
                    if p.returncode != 0: return False
                    for i, ip in enumerate(v4_ips[1:], start=2):
                        p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'add', 'dns', f'name="{interface}"', ip, f'index={i}', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        await p.communicate()
                        if p.returncode != 0: return False
                        
            if dns_data.get("v6_mode") == "DHCP":
                p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ipv6', 'set', 'dns', f'name="{interface}"', 'source=dhcp', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0: return False
            else:
                v6_ips = dns_data.get("v6_servers", [])
                if v6_ips:
                    p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ipv6', 'set', 'dns', f'name="{interface}"', 'static', v6_ips[0], 'primary', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    await p.communicate()
                    if p.returncode != 0: return False
                    for i, ip in enumerate(v6_ips[1:], start=2):
                        p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ipv6', 'add', 'dns', f'name="{interface}"', ip, f'index={i}', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        await p.communicate()
                        if p.returncode != 0: return False
                        
            p_flush = await asyncio.create_subprocess_exec('ipconfig', '/flushdns', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await p_flush.communicate()
        elif system == 'darwin':
            if original_dns and "There aren't any DNS Servers" not in original_dns:
                dns_list = original_dns.split()
                p = await asyncio.create_subprocess_exec('networksetup', '-setdnsservers', interface, *dns_list, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0: return False
            else:
                p = await asyncio.create_subprocess_exec('networksetup', '-setdnsservers', interface, 'empty', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0: return False
        else:
            if shutil.which('resolvectl'):
                if original_dns and original_dns != "EMPTY":
                    dns_ips = original_dns.split()
                    p = await asyncio.create_subprocess_exec('resolvectl', 'dns', interface, *dns_ips, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    await p.communicate()
                    if p.returncode != 0: return False
                else:
                    p = await asyncio.create_subprocess_exec('resolvectl', 'revert', interface, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    await p.communicate()
                    if p.returncode != 0: return False
            else:
                return False
                
        state['dns_changed'] = False
        state['dns_backed_up'] = False
        state.pop('original_dns', None)
        save_state(state)
        log("System DNS restored to original settings.", "PASS")
        return True
    except Exception as e:
        logger.error(f"DNS restore error: {e}")
        return False

def b64_decode(s):
    s = s.replace('-', '+').replace('_', '/')
    missing = len(s) % 4
    if missing: s += '=' * (4 - missing)
    return base64.b64decode(s).decode('utf-8')

def parse_config_link(link):
    try:
        parsed = urlparse(link)
        proto = parsed.scheme
        params = parse_qs(parsed.query)
        creds = {"protocol": proto, "raw_link": link}
        
        if not parsed.hostname or not parsed.port:
            creds["protocol"] = "unsupported"
            return creds
            
        if proto == "vless":
            if not parsed.username: raise ValueError("Missing VLESS UUID")
            creds["vless_server_ip"] = parsed.hostname
            creds["vless_port"] = parsed.port or 443
            creds["vless_uuid"] = unquote(parsed.username)
            creds["vless_security"] = params.get("security", ["none"])[0]
            creds["vless_type"] = params.get("type", ["tcp"])[0]
            creds["vless_sni"] = params.get("sni", [""])[0]
            creds["vless_host"] = params.get("host", [""])[0]
            creds["vless_path"] = unquote(params.get("path", ["/"])[0])
            creds["vless_public_key"] = params.get("pbk", [""])[0]
            creds["vless_short_id"] = params.get("sid", [""])[0]
            creds["vless_service_name"] = params.get("serviceName", [""])[0]
            creds["vless_flow"] = params.get("flow", [""])[0]
        elif proto == "trojan":
            if not parsed.username: raise ValueError("Missing Trojan password")
            creds["trojan_server_ip"] = parsed.hostname
            creds["trojan_port"] = parsed.port or 443
            creds["trojan_password"] = unquote(parsed.username)
            creds["trojan_domain"] = params.get("sni", [""])[0]
        elif proto in ("hysteria2", "hy2"):
            if not parsed.username: raise ValueError("Missing Hysteria2 password")
            creds["hysteria_server_ip"] = parsed.hostname
            creds["hysteria_port"] = parsed.port or 443
            creds["hysteria_password"] = unquote(parsed.username)
            creds["hysteria_sni"] = params.get("sni", [""])[0]
            creds["hysteria_insecure"] = params.get("insecure", ["0"])[0] == "1"
            creds["hysteria_obfs"] = params.get("obfs", [""])[0]
            creds["hysteria_obfs_password"] = params.get("obfs-password", [""])[0]
        elif proto == "shadowtls":
            if not parsed.username: raise ValueError("Missing ShadowTLS password")
            creds["shadowtls_server_ip"] = parsed.hostname
            creds["shadowtls_port"] = parsed.port or 443
            creds["shadowtls_password"] = unquote(parsed.username)
            creds["shadowtls_sni"] = params.get("sni", [""])[0]
        elif proto == "tuic":
            if not parsed.username: raise ValueError("Missing TUIC UUID")
            creds["tuic_server_ip"] = parsed.hostname
            creds["tuic_port"] = parsed.port or 443
            creds["tuic_uuid"] = unquote(parsed.username)
            creds["tuic_password"] = params.get("password", [""])[0]
            creds["tuic_sni"] = params.get("sni", [""])[0]
            creds["tuic_alpn"] = params.get("alpn", ["h3"])[0]
            creds["tuic_insecure"] = params.get("insecure", ["0"])[0] == "1"
        elif proto in ("naive+https", "naive"):
            if not parsed.username or not parsed.password: raise ValueError("Missing Naive credentials")
            creds["naive_server_ip"] = parsed.hostname
            creds["naive_port"] = parsed.port or 443
            creds["naive_user"] = unquote(parsed.username)
            creds["naive_password"] = unquote(parsed.password)
            creds["naive_sni"] = params.get("sni", [""])[0]
        elif proto == "vmess":
            try:
                raw_b64 = parsed.path[1:]
                decoded = b64_decode(raw_b64)
                vmess_data = json.loads(decoded)
                creds["vmess_server_ip"] = vmess_data.get("add")
                creds["vmess_port"] = int(vmess_data.get("port", 443))
                creds["vmess_uuid"] = vmess_data.get("id")
                creds["vmess_security"] = vmess_data.get("scy", "auto")
                creds["vmess_type"] = vmess_data.get("net", "tcp")
                creds["vmess_sni"] = vmess_data.get("sni", "")
                creds["vmess_host"] = vmess_data.get("host", "")
                creds["vmess_path"] = unquote(vmess_data.get("path", "/"))
                creds["vmess_service_name"] = vmess_data.get("serviceName", "")
                if not creds["vmess_service_name"] and creds["vmess_type"] == "grpc":
                    creds["vmess_service_name"] = creds["vmess_path"]
                creds["vmess_tls"] = vmess_data.get("tls", "")
                creds["vmess_alter_id"] = int(vmess_data.get("aid", 0))
            except Exception as e:
                logger.error(f"VMess parse error: {e}")
                creds["protocol"] = "unsupported"
        elif proto == "ss":
            try:
                if "@" in parsed.netloc:
                    userinfo, hostport = parsed.netloc.rsplit("@", 1)
                    if ":" in userinfo:
                        method, password = userinfo.split(":", 1)
                    else:
                        decoded = b64_decode(userinfo)
                        method, password = decoded.split(":", 1)
                    creds["ss_server_ip"] = parsed.hostname
                    creds["ss_port"] = parsed.port or 443
                    creds["ss_method"] = method
                    creds["ss_password"] = password
                else:
                    decoded = b64_decode(parsed.netloc)
                    method_pass, hostport = decoded.rsplit("@", 1)
                    method, password = method_pass.split(":", 1)
                    if hostport.startswith("["):
                        ip_str, port_str = hostport.rsplit(":", 1)
                        creds["ss_server_ip"] = ip_str.strip("[]")
                        creds["ss_port"] = int(port_str)
                    else:
                        creds["ss_server_ip"] = hostport.split(":")[0]
                        creds["ss_port"] = int(hostport.split(":")[1])
                    creds["ss_method"] = method
                    creds["ss_password"] = password
            except Exception as e:
                logger.error(f"SS parse error: {e}")
                creds["protocol"] = "unsupported"
        else: creds["protocol"] = "unsupported"
        return creds
    except Exception as e:
        logger.error(f"Failed to parse config {link}: {e}")
        return {"protocol": "unsupported", "raw_link": link}

def get_proto_prefix(proto):
    if proto in ("hysteria2", "hy2"): return "hysteria"
    if proto in ("naive+https", "naive"): return "naive"
    return proto

async def check_config_latency(creds):
    async with latency_sem:
        proto = creds["protocol"]
        prefix = get_proto_prefix(proto)
        host = creds.get(f"{prefix}_server_ip")
        port = creds.get(f"{prefix}_port")
        if not host or not port: return None
        if proto not in ("hysteria2", "hy2", "tuic", "warp", "cloudflare_worker", "tor_snowflake", "warp_over_reality", "tor_proxy", "psiphon", "dnstt"):
            try:
                start = time.time()
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
                latency = round((time.time() - start) * 1000, 2)
                writer.close(); await writer.wait_closed()
                return latency
            except Exception as e:
                logger.debug(f"Latency check error: {e}")
                return None
        else:
            for p in [443, 80, port]:
                try:
                    start = time.time()
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, p), timeout=2)
                    latency = round((time.time() - start) * 1000, 2)
                    writer.close(); await writer.wait_closed()
                    return latency
                except Exception:
                    continue
            return await get_icmp_latency(host)

def get_dynamic_tls_settings(dpi_state='none'):
    fingerprints = ["chrome", "firefox", "safari", "edge", "ios", "random"]
    if dpi_state in ['aggressive', 'rst']:
        lengths = ["10-50", "50-100", "20-80", "100-200"]
        intervals = ["1-3", "3-5", "5-10"]
    else:
        lengths = ["50-100", "100-200", "200-300"]
        intervals = ["5-10", "10-15"]
    return {
        "fingerprint": random.choice(fingerprints),
        "fragment": {"packets": "tlshello", "length": random.choice(lengths), "interval": random.choice(intervals)}
    }

async def generate_bypass_config(creds, all_configs=None, dpi_state='none'):
    log("Action: Generating optimized bypass config...", "SOL")
    use_tun = False 
    routing_rules = {
        "domainStrategy": "AsIs", "strictRoute": use_tun,
        "rules": [
            {"type": "field", "outboundTag": "block", "port": "137-139", "network": "tcp,udp"},
            {"type": "field", "outboundTag": "block", "ip": ["224.0.0.0/8", "169.254.0.0/16", "255.255.255.255/32"]},
            {"type": "field", "outboundTag": "dns-out", "port": 53, "network": "tcp,udp"},
            {"type": "field", "outboundTag": "direct", "domain": ["geosite:category-ir", "domain:ir"]},
            {"type": "field", "outboundTag": "direct", "ip": ["geoip:ir", "geoip:private"]}
        ]
    }
    dynamic_tls = get_dynamic_tls_settings(dpi_state)
    mux_settings = {"enabled": False, "concurrency": -1}
    
    common_inbounds = [
        {"port": LOCAL_SOCKS_PORT, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
        {"port": LOCAL_HTTP_PORT, "listen": "127.0.0.1", "protocol": "http", "settings": {}} 
    ]
    
    common_dns = {"servers": ["https+local://8.8.8.8/dns-query", "localhost"], "queryStrategy": "UseIP"}

    def apply_fragmentation(ob):
        if "streamSettings" not in ob: ob["streamSettings"] = {}
        if "sockopt" not in ob["streamSettings"]: ob["streamSettings"]["sockopt"] = {}
        ob["streamSettings"]["sockopt"]["dialerProxy"] = "fragment-out"
        ob["streamSettings"]["sockopt"]["tcpNoDelay"] = True
        return ob

    def apply_tcp_nodelay(ob):
        if "streamSettings" not in ob: ob["streamSettings"] = {}
        if "sockopt" not in ob["streamSettings"]: ob["streamSettings"]["sockopt"] = {}
        ob["streamSettings"]["sockopt"]["tcpNoDelay"] = True
        return ob

    if creds["protocol"] == "warp_over_reality":
        warp_data = creds.get("warp_data"); reality_config = creds.get("reality_config")
        if not warp_data or not reality_config: return None, None
        flow = reality_config.get("vless_flow") or "xtls-rprx-vision"
        sni_val = reality_config.get("vless_sni") or get_less_popular_sni()
        reality_outbound = {
            "tag": "reality_tunnel", "protocol": "vless",
            "settings": {"vnext": [{"address": reality_config["vless_server_ip"], "port": reality_config["vless_port"], "users": [{"id": reality_config["vless_uuid"], "encryption": "none", "flow": flow}]}]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": sni_val, "publicKey": reality_config["vless_public_key"], "shortId": reality_config["vless_short_id"], "spiderX": random_spider_x()}}
        }
        reality_outbound = apply_fragmentation(reality_outbound)
        warp_outbound = {
            "tag": "proxy", "protocol": "wireguard", "proxySettings": {"tag": "reality_tunnel"},
            "settings": {
                "secretKey": warp_data.get("private_key", ""),
                "address": [warp_data.get("ipv4_address", ""), warp_data.get("ipv6_address", "")],
                "peers": [{"publicKey": warp_data.get("peer_public_key", ""), "allowedIPs": ["0.0.0.0/0", "::/0"], "endpoint": "162.159.192.1:2408"}],
                "reserved": warp_data.get("reserved", [0, 0, 0]),
                "kernelMode": False
            }
        }
        config = {"log": {"loglevel": "warning"}, "dns": common_dns, "inbounds": common_inbounds, "outbounds": [warp_outbound, reality_outbound, {"tag": "dns-out", "protocol": "dns"}, {"tag": "direct", "protocol": "freedom"}], "routing": routing_rules}
        atomic_write_json(os.path.join(DATA_DIR, "auto_bypass_config_warp_reality.json"), config)
        return "auto_bypass_config_warp_reality.json", "xray"

    if creds["protocol"] == "warp":
        warp_data = creds.get("warp_data")
        if not warp_data: return None, None
        endpoint = creds.get("custom_endpoint", warp_data.get("endpoint", "162.159.192.1:2408"))
        config = {
            "log": {"loglevel": "warning"}, "dns": common_dns, "inbounds": common_inbounds,
            "outbounds": [
                {"tag": "proxy", "protocol": "wireguard", "settings": {"secretKey": warp_data.get("private_key", ""), "address": [warp_data.get("ipv4_address", ""), warp_data.get("ipv6_address", "")], "peers": [{"publicKey": warp_data.get("peer_public_key", ""), "allowedIPs": ["0.0.0.0/0", "::/0"], "endpoint": endpoint}], "reserved": warp_data.get("reserved", [0, 0, 0]), "kernelMode": False, "mtu": 1280}},
                {"tag": "dns-out", "protocol": "dns"}, {"tag": "direct", "protocol": "freedom"}
            ],
            "routing": routing_rules
        }
        atomic_write_json(os.path.join(DATA_DIR, "auto_bypass_config_warp.json"), config)
        return "auto_bypass_config_warp.json", "xray"

    if creds["protocol"] in ("hysteria2", "hy2"):
        config = {
            "server": f"{creds['hysteria_server_ip']}:{creds['hysteria_port']}", "auth": creds["hysteria_password"],
            "tls": {"sni": creds["hysteria_sni"], "insecure": creds["hysteria_insecure"]},
            "socks5": {"listen": f"127.0.0.1:{LOCAL_SOCKS_PORT}"}, "http": {"listen": f"127.0.0.1:{LOCAL_HTTP_PORT}"},
            "up": "100 Mbps", "down": "100 Mbps"
        }
        if creds["hysteria_obfs"]:
            config["obfs"] = {"type": creds["hysteria_obfs"]}
            if creds["hysteria_obfs"] == "salamander":
                config["obfs"]["salamander"] = {"password": creds["hysteria_obfs_password"]}
        atomic_write_json(os.path.join(DATA_DIR, "auto_bypass_config_hy2.json"), config)
        return "auto_bypass_config_hy2.json", "hysteria"

    if creds["protocol"] == "tuic":
        config = {
            "server": f"{creds['tuic_server_ip']}:{creds['tuic_port']}", "uuid": creds["tuic_uuid"], "password": creds["tuic_password"],
            "tls": {"sni": creds["tuic_sni"], "alpn": [creds["tuic_alpn"]], "insecure": creds["tuic_insecure"]},
            "socks5": {"listen": f"127.0.0.1:{LOCAL_SOCKS_PORT}"}, "http": {"listen": f"127.0.0.1:{LOCAL_HTTP_PORT}"},
            "udp_relay_mode": "native",
            "congestion_control": "bbr"
        }
        atomic_write_json(os.path.join(DATA_DIR, "auto_bypass_config_tuic.json"), config)
        return "auto_bypass_config_tuic.json", "tuic"

    if creds["protocol"] in ("naive+https", "naive"):
        config = {"listen": f"http://127.0.0.1:{LOCAL_HTTP_PORT}", "proxy": f"https://{creds['naive_user']}:{creds['naive_password']}@{creds['naive_server_ip']}:{creds['naive_port']}"}
        if creds.get("naive_sni"):
            config["host-resolver-rules"] = f"SN,{creds['naive_sni']}"
        atomic_write_json(os.path.join(DATA_DIR, "auto_bypass_config_naive.json"), config)
        return "auto_bypass_config_naive.json", "naive"

    if creds["protocol"] == "psiphon":
        psiphon_config = {
            "PropagationChannelId": "FFFFFFFFFFFFFFFF",
            "RemoteServerListURLs": [
                {"URLFormat": "https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed", "SignaturePublicKey": "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvZ9NcPAwW0/J4T0F4xjVqr1Xy2bUHDDQC4iRpvLjoyb/IE1kgroBtQR1Ptg2QzTiEDuZqOHSQjvy37LhOFd0n7d4QOWfX3MGts9CpfA9IyRE0LeGe4O3Dz1m1ZI76t1tWc5q9qY+vYrn6Qp8dWwL6r56Y3pucyD1W1qYwdc8gq5sQm2b9O7BZ9Sa1r1l1e2vKH/1t5xQf1t3t3f1Qv1t1wR1t1sP1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1="}
            ],
            "LocalSocksProxyPort": LOCAL_SOCKS_PORT,
            "LocalHttpProxyPort": LOCAL_HTTP_PORT,
            "DisableLocalSocksProxy": False
        }
        atomic_write_json(os.path.join(DATA_DIR, "psiphon_config.json"), psiphon_config)
        return "psiphon_config.json", "psiphon"

    if creds["protocol"] == "dnstt":
        dnstt_domain = creds.get("dnstt_domain")
        dnstt_pubkey = creds.get("dnstt_pubkey")
        if not dnstt_domain or not dnstt_pubkey: return None, None
        
        local_dntt_port = LOCAL_SOCKS_PORT + 1000
        creds["dnstt_local_port"] = local_dntt_port
        
        config = {
            "log": {"loglevel": "warning"}, "dns": common_dns, "inbounds": common_inbounds,
            "outbounds": [
                {
                    "tag": "proxy", 
                    "protocol": "socks", 
                    "settings": {
                        "servers": [{"address": "127.0.0.1", "port": local_dntt_port}]
                    }
                },
                {"tag": "dns-out", "protocol": "dns"}, {"tag": "direct", "protocol": "freedom"}
            ], "routing": routing_rules
        }
        atomic_write_json(os.path.join(DATA_DIR, "auto_bypass_config_dnstt.json"), config)
        return "auto_bypass_config_dnstt.json", "xray+dnstt"

    if creds["protocol"] == "cloudflare_worker":
        worker_data = creds.get("worker_data")
        if not worker_data or not worker_data.get("id") or not worker_data.get("host"):
            log("Cloudflare Worker ID/Host missing. Skipping.", "WARN")
            return None, None
            
        worker_host = worker_data["host"]
        worker_id   = worker_data["id"]
        worker_path = worker_data.get("path", "/ws")
        
        cf_ip = None
        cdn_provider = worker_data.get("cdn", "cloudflare")
        clean_ips = await scan_clean_cdn_ips(cdn_provider=cdn_provider, worker_host=worker_host, worker_path=worker_path, count=3)
        if clean_ips:
            cf_ip = clean_ips[0]
            log(f"  -> Using scanned {cdn_provider} IP: {cf_ip}", "PASS")
        
        if not cf_ip:
            log("Clean IP scan failed. Cannot proceed with CF Worker safely.", "FAIL")
            return None, None

        config = {
            "log": {"loglevel": "warning"}, "dns": common_dns, "inbounds": common_inbounds,
            "outbounds": [
                {
                    "tag": "proxy", "protocol": "vless", "mux": mux_settings, 
                    "settings": {"vnext": [{"address": cf_ip, "port": 443, "users": [{"id": worker_id, "encryption": "none"}]}]}, 
                    "streamSettings": {
                        "network": "ws", "security": "tls", 
                        "tlsSettings": {"serverName": worker_host, "fingerprint": dynamic_tls["fingerprint"], "minVersion": "1.2"}, 
                        "wsSettings": {"path": worker_path, "headers": {"Host": worker_host}}
                    }
                },
                {"tag": "dns-out", "protocol": "dns"}, {"tag": "direct", "protocol": "freedom"}
            ], "routing": routing_rules
        }
        config["outbounds"][0] = apply_fragmentation(config["outbounds"][0])
        config["outbounds"].append({
            "tag": "fragment-out",
            "protocol": "freedom",
            "settings": {"fragment": dynamic_tls["fragment"]},
            "streamSettings": {"sockopt": {"tcpNoDelay": True}}
        })
        
        atomic_write_json(os.path.join(DATA_DIR, "auto_bypass_config_cf.json"), config)
        return "auto_bypass_config_cf.json", "xray"

    if creds["protocol"] == "tor_snowflake":
        lyrebird_path = LYREBIRD_PATH
        snowflake_path = SF_PATH
        tor_data_dir = os.path.join(DATA_DIR, "tor_data").replace("\\", "/")
        
        if snowflake_path and os.path.isfile(snowflake_path):
            log("Using Snowflake for Tor connection...", "INFO")
            torrc_content = f"""
DataDirectory {tor_data_dir}
SocksPort 127.0.0.1:{LOCAL_SOCKS_PORT}
HTTPTunnelPort 127.0.0.1:{LOCAL_HTTP_PORT}
UseBridges 1
ClientTransportPlugin snowflake exec {snowflake_path}
Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.org,ajax.aspnetcdn.com ice=stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn
Bridge snowflake 192.0.2.4:80 8838024498816A039B6BFF4908B6020058B11D18 fingerprint=8838024498816A039B6BFF4908B6020058B11D18 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.org,ajax.aspnetcdn.com ice=stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn
"""
            config_name = "torrc_snowflake"
            
        elif lyrebird_path and os.path.isfile(lyrebird_path):
            log("snowflake-client not found. Falling back to lyrebird (obfs4 only).", "WARN")
            torrc_content = f"""
DataDirectory {tor_data_dir}
SocksPort 127.0.0.1:{LOCAL_SOCKS_PORT}
HTTPTunnelPort 127.0.0.1:{LOCAL_HTTP_PORT}
UseBridges 1
ClientTransportPlugin obfs4 exec {lyrebird_path}
Bridge obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1
Bridge obfs4 38.229.1.78:80 C8CBDB2464FC9804A69531437BCF2BE31FDD2EE4 cert=AA1+Qiae9pr5f17V01d3XvqP1TZw5B6G6XG5RZKmYjKPEAo6V0T+AQAU5ADQ iat-mode=1
Bridge obfs4 141.95.111.83:443 8C96E49E5AAECF3F779E1D401E0505B96C1365A1 cert=8C96E49E5AAECF3F779E1D401E0505B96C1365A1+8C96E49E5AAECF3F779E1D401E0505B96C1365A1 iat-mode=0
"""
            config_name = "torrc_obfs4"
            
        else:
            log("Neither snowflake-client.exe nor lyrebird.exe found. Tor will fail.", "ERROR")
            return None, None
            
        with open(os.path.join(DATA_DIR, config_name), "w") as f:
            f.write(torrc_content)
        return config_name, "tor"

    if creds["protocol"] == "tor_proxy":
        log("Using Tor Network (Direct Tor Proxy)...", "INFO")
        tor_data_dir = os.path.join(DATA_DIR, "tor_data").replace("\\", "/")
        torrc_content = f"""
DataDirectory {tor_data_dir}
SocksPort 127.0.0.1:{LOCAL_SOCKS_PORT}
HTTPTunnelPort 127.0.0.1:{LOCAL_HTTP_PORT}
"""
        with open(os.path.join(DATA_DIR, "torrc_proxy"), "w") as f: f.write(torrc_content)
        return "torrc_proxy", "tor"

    use_balancer = all_configs and len(all_configs) > 1
    config = {"log": {"loglevel": "warning"}, "dns": common_dns, "inbounds": common_inbounds, "outbounds": [], "routing": routing_rules}

    def make_vless_reality_outbound(c, tag="proxy"):
        sni = c.get("vless_sni") or get_less_popular_sni()
        flow = c.get("vless_flow") or "xtls-rprx-vision"
        ob = {"tag": tag, "protocol": "vless", "settings": {"vnext": [{"address": c["vless_server_ip"], "port": c["vless_port"], "users": [{"id": c["vless_uuid"], "encryption": "none", "flow": flow}]}]}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": sni, "fingerprint": dynamic_tls["fingerprint"], "publicKey": c["vless_public_key"], "shortId": c["vless_short_id"], "spiderX": random_spider_x()}}}
        return apply_fragmentation(ob)

    def make_vless_ws_outbound(c, tag="proxy"):
        host = c.get("vless_host") or c.get("vless_sni", "")
        ob = {"tag": tag, "protocol": "vless", "mux": mux_settings, "settings": {"vnext": [{"address": c["vless_server_ip"], "port": c["vless_port"], "users": [{"id": c["vless_uuid"], "encryption": "none"}]}]}, "streamSettings": {"network": "ws", "security": c.get("vless_security", "none"), "wsSettings": {"path": c["vless_path"], "headers": {"Host": host}}}}
        if c.get("vless_security") == "tls":
            sni_val = c.get("vless_sni", "")
            ob["streamSettings"]["tlsSettings"] = {"serverName": sni_val, "fingerprint": dynamic_tls["fingerprint"], "minVersion": "1.2"}
            ob = apply_fragmentation(ob)
        else:
            ob = apply_tcp_nodelay(ob)
        return ob

    def make_vless_grpc_outbound(c, tag="proxy"):
        ob = {"tag": tag, "protocol": "vless", "mux": mux_settings, "settings": {"vnext": [{"address": c["vless_server_ip"], "port": c["vless_port"], "users": [{"id": c["vless_uuid"], "encryption": "none"}]}]}, "streamSettings": {"network": "grpc", "security": c.get("vless_security", "none"), "grpcSettings": {"serviceName": c.get("vless_service_name", "")}}}
        if c.get("vless_security") == "tls":
            sni_val = c.get("vless_sni", "")
            ob["streamSettings"]["tlsSettings"] = {"serverName": sni_val, "fingerprint": dynamic_tls["fingerprint"], "minVersion": "1.2"}
            ob = apply_fragmentation(ob)
        else:
            ob = apply_tcp_nodelay(ob)
        return ob

    def make_trojan_outbound(c, tag="proxy"):
        sni_val = c.get("trojan_domain", "")
        ob = {
            "tag": tag, 
            "protocol": "trojan", 
            "mux": mux_settings, 
            "settings": {
                "servers": [
                    {
                        "address": c["trojan_server_ip"], 
                        "port": c["trojan_port"], 
                        "password": c["trojan_password"]
                    }
                ]
            }, 
            "streamSettings": {
                "network": "tcp", 
                "security": "tls", 
                "tlsSettings": {
                    "serverName": sni_val, 
                    "fingerprint": dynamic_tls["fingerprint"], 
                    "minVersion": "1.2"
                }
            }
        }
        return apply_fragmentation(ob)

    def make_shadowtls_outbound(c, tag="proxy"):
        sni_val = c.get("shadowtls_sni", "") or get_less_popular_sni()
        ob = {
            "tag": tag, 
            "protocol": "shadowtls", 
            "settings": {
                "servers": [{
                    "address": c["shadowtls_server_ip"], 
                    "port": c["shadowtls_port"], 
                    "password": c["shadowtls_password"]
                }]
            }, 
            "streamSettings": {
                "network": "tcp", 
                "security": "tls", 
                "tlsSettings": {
                    "serverName": sni_val, 
                    "fingerprint": dynamic_tls["fingerprint"], 
                    "minVersion": "1.2"
                }
            }
        }
        return apply_fragmentation(ob)

    def make_vmess_outbound(c, tag="proxy"):
        ob = {"tag": tag, "protocol": "vmess", "mux": mux_settings, "settings": {"vnext": [{"address": c["vmess_server_ip"], "port": c["vmess_port"], "users": [{"id": c["vmess_uuid"], "security": c["vmess_security"], "alterId": c.get("vmess_alter_id", 0)}]}]}}
        stream = {"network": c["vmess_type"]}
        if c["vmess_type"] == "ws": 
            host = c["vmess_host"] or c["vmess_sni"]
            stream["wsSettings"] = {"path": c["vmess_path"], "headers": {"Host": host}}
        elif c["vmess_type"] == "grpc": 
            stream["grpcSettings"] = {"serviceName": c.get("vmess_service_name", "")}
        elif c["vmess_type"] == "http":
            stream["httpSettings"] = {"path": c["vmess_path"], "host": [c["vmess_host"]]}
        if c["vmess_tls"] == "tls":
            sni_val = c["vmess_sni"]
            stream["security"] = "tls"; stream["tlsSettings"] = {"serverName": sni_val, "fingerprint": dynamic_tls["fingerprint"], "minVersion": "1.2"}
            ob["streamSettings"] = stream
            ob = apply_fragmentation(ob)
        else:
            stream["security"] = "none"
            ob["streamSettings"] = stream
            ob = apply_tcp_nodelay(ob)
        return ob

    def make_ss_outbound(c, tag="proxy"):
        ob = {"tag": tag, "protocol": "shadowsocks", "settings": {"servers": [{"address": c["ss_server_ip"], "port": c["ss_port"], "method": c["ss_method"], "password": c["ss_password"]}]}}
        return apply_tcp_nodelay(ob)

    def make_outbound_for(c, tag="proxy"):
        if c["protocol"] == "vless":
            if c.get("vless_security") == "reality": return make_vless_reality_outbound(c, tag)
            elif c.get("vless_type") == "ws": return make_vless_ws_outbound(c, tag)
            elif c.get("vless_type") == "grpc": return make_vless_grpc_outbound(c, tag)
            elif c.get("vless_type") == "tcp":
                ob = {"tag": tag, "protocol": "vless", "mux": mux_settings, "settings": {"vnext": [{"address": c["vless_server_ip"], "port": c["vless_port"], "users": [{"id": c["vless_uuid"], "encryption": "none"}]}]}, "streamSettings": {"network": "tcp"}}
                if c.get("vless_security") == "tls":
                    ob["streamSettings"]["security"] = "tls"
                    ob["streamSettings"]["tlsSettings"] = {"serverName": c.get("vless_sni", ""), "fingerprint": dynamic_tls["fingerprint"], "minVersion": "1.2"}
                    ob = apply_fragmentation(ob)
                else:
                    ob["streamSettings"]["security"] = "none"
                    ob = apply_tcp_nodelay(ob)
                return ob
            else: 
                logger.warning(f"Unsupported VLESS transport: {c.get('vless_type')}")
                return None
        elif c["protocol"] == "trojan": return make_trojan_outbound(c, tag)
        elif c["protocol"] == "shadowtls": return make_shadowtls_outbound(c, tag)
        elif c["protocol"] == "vmess": return make_vmess_outbound(c, tag)
        elif c["protocol"] == "ss": return make_ss_outbound(c, tag)
        return None

    if dpi_state in ['aggressive', 'rst', 'drop'] and all_configs:
        shadowtls_cfg = next((c for c in all_configs if c["protocol"] == "shadowtls"), None)
        if shadowtls_cfg and creds["protocol"] not in ("shadowtls",):
            outer_ob = make_shadowtls_outbound(shadowtls_cfg, "outer_shadowtls_layer")
            if outer_ob:
                config["outbounds"].append(outer_ob)
                
                inner_ob = make_outbound_for(creds, "proxy")
                if inner_ob:
                    if "streamSettings" not in inner_ob: inner_ob["streamSettings"] = {}
                    if "sockopt" not in inner_ob["streamSettings"]: inner_ob["streamSettings"]["sockopt"] = {}
                    inner_ob["streamSettings"]["sockopt"]["dialerProxy"] = "outer_shadowtls_layer"
                    inner_ob["streamSettings"]["sockopt"]["tcpNoDelay"] = True
                    config["outbounds"].append(inner_ob)
                    
                    config["outbounds"].append({
                        "tag": "fragment-out",
                        "protocol": "freedom",
                        "settings": {"fragment": dynamic_tls["fragment"]},
                        "streamSettings": {"sockopt": {"tcpNoDelay": True}}
                    })
                    config["outbounds"].append({"tag": "dns-out", "protocol": "dns"})
                    config["outbounds"].append({"tag": "direct", "protocol": "freedom"})
                    config["outbounds"].append({"tag": "block", "protocol": "blackhole"})
                    log("Action: Applied Advanced Proxy Chaining (Inner Proxy -> ShadowTLS Outer Layer)", "SOL")
                    atomic_write_json(os.path.join(DATA_DIR, "auto_bypass_config_xray.json"), config)
                    return "auto_bypass_config_xray.json", "xray"

        reality_cfg = next((c for c in all_configs if c["protocol"] == "vless" and c.get("vless_security") == "reality"), None)
        if reality_cfg and creds["protocol"] not in ("vless", "reality"):
            outer_ob = make_vless_reality_outbound(reality_cfg, "outer_reality_layer")
            if outer_ob:
                config["outbounds"].append(outer_ob)
                
                inner_ob = make_outbound_for(creds, "proxy")
                if inner_ob:
                    if "streamSettings" not in inner_ob: inner_ob["streamSettings"] = {}
                    if "sockopt" not in inner_ob["streamSettings"]: inner_ob["streamSettings"]["sockopt"] = {}
                    inner_ob["streamSettings"]["sockopt"]["dialerProxy"] = "outer_reality_layer"
                    inner_ob["streamSettings"]["sockopt"]["tcpNoDelay"] = True
                    config["outbounds"].append(inner_ob)
                    
                    config["outbounds"].append({
                        "tag": "fragment-out",
                        "protocol": "freedom",
                        "settings": {"fragment": dynamic_tls["fragment"]},
                        "streamSettings": {"sockopt": {"tcpNoDelay": True}}
                    })
                    config["outbounds"].append({"tag": "dns-out", "protocol": "dns"})
                    config["outbounds"].append({"tag": "direct", "protocol": "freedom"})
                    config["outbounds"].append({"tag": "block", "protocol": "blackhole"})
                    log("Action: Applied Advanced Proxy Chaining (Inner Proxy -> Reality Outer Layer)", "SOL")
                    atomic_write_json(os.path.join(DATA_DIR, "auto_bypass_config_xray.json"), config)
                    return "auto_bypass_config_xray.json", "xray"

    if use_balancer:
        balancer_tags = []
        for idx, c in enumerate(all_configs):
            tag = f"proxy_{idx}"; ob = make_outbound_for(c, tag)
            if ob: 
                ob = apply_fragmentation(ob)
                config["outbounds"].append(ob); balancer_tags.append(tag)
        if balancer_tags:
            config["routing"]["balancers"] = [{"tag": "balancer", "selector": balancer_tags, "fallbackTag": balancer_tags[0], "strategy": {"type": "leastPing"}}]
            config["routing"]["rules"].insert(0, {"type": "field", "balancerTag": "balancer", "network": "tcp,udp"})
            
            config["observatory"] = {
                "subjectSelect": balancer_tags,
                "probeURL": "https://www.gstatic.com/generate_204",
                "probeInterval": "30s",
                "enableConcurrency": True
            }
        else:
            ob = make_outbound_for(creds, "proxy")
            if ob: config["outbounds"].append(ob)
    else:
        ob = make_outbound_for(creds, "proxy")
        if not ob: return None, None
        config["outbounds"].append(ob)
    
    config["outbounds"].append({
        "tag": "fragment-out",
        "protocol": "freedom",
        "settings": {"fragment": dynamic_tls["fragment"]},
        "streamSettings": {"sockopt": {"tcpNoDelay": True}}
    })
    
    config["outbounds"].append({"tag": "dns-out", "protocol": "dns"})
    config["outbounds"].append({"tag": "direct", "protocol": "freedom"})
    config["outbounds"].append({"tag": "block", "protocol": "blackhole"})
    atomic_write_json(os.path.join(DATA_DIR, "auto_bypass_config_xray.json"), config)
    return "auto_bypass_config_xray.json", "xray"

async def get_current_proxy():
    system = platform.system().lower()
    try:
        if system == 'windows':
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, winreg.KEY_READ)
            enable, _ = winreg.QueryValueEx(key, 'ProxyEnable')
            server = ""
            override = ""
            try: server, _ = winreg.QueryValueEx(key, 'ProxyServer')
            except: pass
            try: override, _ = winreg.QueryValueEx(key, 'ProxyOverride')
            except: pass
            winreg.CloseKey(key)
            return {"valid": True, "enabled": bool(enable), "server": server, "override": override}
        elif system == 'darwin':
            interface = await get_default_interface()
            proc = await asyncio.create_subprocess_exec('networksetup', '-getwebproxy', interface, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await proc.communicate()
            out = stdout.decode()
            enabled = "Enabled: Yes" in out
            server = re.search(r"Server: (\S+)", out)
            port = re.search(r"Port: (\d+)", out)
            
            sproc = await asyncio.create_subprocess_exec('networksetup', '-getsecurewebproxy', interface, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            sout, _ = await sproc.communicate()
            sout_str = sout.decode()
            s_enabled = "Enabled: Yes" in sout_str
            s_server = re.search(r"Server: (\S+)", sout_str)
            s_port = re.search(r"Port: (\d+)", sout_str)
            
            bproc = await asyncio.create_subprocess_exec('networksetup', '-getproxybypassdomains', interface, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            bstdout, _ = await bproc.communicate()
            bypass = bstdout.decode().strip()
            
            return {
                "valid": True,
                "web_enabled": enabled, 
                "secure_enabled": s_enabled, 
                "server": f"{server.group(1)}:{port.group(1)}" if server and port else "",
                "secure_server": f"{s_server.group(1)}:{s_port.group(1)}" if s_server and s_port else "",
                "bypass": bypass
            }
        else:
            if not shutil.which('gsettings'):
                return {"valid": False, "enabled": False, "server": ""}
            mode_proc = await asyncio.create_subprocess_exec('gsettings', 'get', 'org.gnome.system.proxy', 'mode', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await mode_proc.communicate()
            mode = stdout.decode().strip().strip("'")
            if mode == 'manual':
                host_proc = await asyncio.create_subprocess_exec('gsettings', 'get', 'org.gnome.system.proxy.http', 'host', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                host, _ = await host_proc.communicate()
                port_proc = await asyncio.create_subprocess_exec('gsettings', 'get', 'org.gnome.system.proxy.http', 'port', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                port, _ = await port_proc.communicate()
                
                shost_proc = await asyncio.create_subprocess_exec('gsettings', 'get', 'org.gnome.system.proxy.https', 'host', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                shost, _ = await shost_proc.communicate()
                sport_proc = await asyncio.create_subprocess_exec('gsettings', 'get', 'org.gnome.system.proxy.https', 'port', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                sport, _ = await sport_proc.communicate()

                fhost_proc = await asyncio.create_subprocess_exec('gsettings', 'get', 'org.gnome.system.proxy.ftp', 'host', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                fhost, _ = await fhost_proc.communicate()
                fport_proc = await asyncio.create_subprocess_exec('gsettings', 'get', 'org.gnome.system.proxy.ftp', 'port', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                fport, _ = await fport_proc.communicate()
                
                ignore_proc = await asyncio.create_subprocess_exec('gsettings', 'get', 'org.gnome.system.proxy', 'ignore-hosts', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                ignore, _ = await ignore_proc.communicate()
                
                http_host = host.decode().strip().strip("'")
                https_host = shost.decode().strip().strip("'")
                ftp_host = fhost.decode().strip().strip("'")
                
                return {
                    "valid": True, 
                    "enabled": True, 
                    "http_enabled": bool(http_host),
                    "server": f"{http_host}:{port.decode().strip().strip("'")}" if http_host else "",
                    "https_enabled": bool(https_host),
                    "secure_server": f"{https_host}:{sport.decode().strip().strip("'")}" if https_host else "",
                    "ftp_enabled": bool(ftp_host),
                    "ftp_server": f"{ftp_host}:{fport.decode().strip().strip("'")}" if ftp_host else "",
                    "ignore_hosts": ignore.decode().strip()
                }
            return {"valid": True, "enabled": False, "server": ""}
    except Exception as e:
        logger.error(f"Failed to get current proxy: {e}")
        return {"valid": False, "enabled": False, "server": ""}

async def restore_system_proxy():
    state = load_state()
    if not state.get('proxy_backed_up'): 
        return True
        
    original = state.get('original_proxy', {})
    if not original.get("valid"): return False
    system = platform.system().lower()
    
    try:
        if system == 'windows':
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, winreg.KEY_ALL_ACCESS)
            if original.get("enabled"):
                winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
            else:
                winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
            if original.get("server"):
                winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, original["server"])
            else:
                try: winreg.DeleteValue(key, 'ProxyServer')
                except: pass
            if original.get("override"):
                winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, original["override"])
            else:
                try: winreg.DeleteValue(key, 'ProxyOverride')
                except: pass
            winreg.CloseKey(key)
            ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0); ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
        elif system == 'darwin':
            interface = await get_default_interface()
            web_enabled = original.get("web_enabled", False)
            sec_enabled = original.get("secure_enabled", False)
            
            if web_enabled and original.get("server"):
                host, port = original["server"].rsplit(":", 1)
                host = host.strip("[]")
                p = await asyncio.create_subprocess_exec('networksetup', '-setwebproxy', interface, host, port, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0: return False
            else:
                p = await asyncio.create_subprocess_exec('networksetup', '-setwebproxystate', interface, 'off', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0: return False
                
            if sec_enabled and original.get("secure_server"):
                host, port = original["secure_server"].rsplit(":", 1)
                host = host.strip("[]")
                p = await asyncio.create_subprocess_exec('networksetup', '-setsecurewebproxy', interface, host, port, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0: return False
            else:
                p = await asyncio.create_subprocess_exec('networksetup', '-setsecurewebproxystate', interface, 'off', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0: return False
                
            if original.get("bypass"):
                bypass_domains = original["bypass"].splitlines()
                if bypass_domains and "There aren't any bypass domains" not in bypass_domains[0]:
                    p = await asyncio.create_subprocess_exec('networksetup', '-setproxybypassdomains', interface, *bypass_domains, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    await p.communicate()
                    if p.returncode != 0: return False
        else:
            if not shutil.which('gsettings'):
                return False
            if original.get("enabled") and original.get("server"):
                cmds = [['gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'manual']]
                
                if original.get("http_enabled") and original.get("server"):
                    h, p = original["server"].rsplit(":", 1)
                    cmds.append(['gsettings', 'set', 'org.gnome.system.proxy.http', 'host', h.strip("[]")])
                    cmds.append(['gsettings', 'set', 'org.gnome.system.proxy.http', 'port', p])
                else:
                    cmds.append(['gsettings', 'set', 'org.gnome.system.proxy.http', 'host', ""])
                    
                if original.get("https_enabled") and original.get("secure_server"):
                    h, p = original["secure_server"].rsplit(":", 1)
                    cmds.append(['gsettings', 'set', 'org.gnome.system.proxy.https', 'host', h.strip("[]")])
                    cmds.append(['gsettings', 'set', 'org.gnome.system.proxy.https', 'port', p])
                else:
                    cmds.append(['gsettings', 'set', 'org.gnome.system.proxy.https', 'host', ""])
                    
                if original.get("ftp_enabled") and original.get("ftp_server"):
                    h, p = original["ftp_server"].rsplit(":", 1)
                    cmds.append(['gsettings', 'set', 'org.gnome.system.proxy.ftp', 'host', h.strip("[]")])
                    cmds.append(['gsettings', 'set', 'org.gnome.system.proxy.ftp', 'port', p])
                else:
                    cmds.append(['gsettings', 'set', 'org.gnome.system.proxy.ftp', 'host', ""])
                    
                if original.get("ignore_hosts"):
                    cmds.append(['gsettings', 'set', 'org.gnome.system.proxy', 'ignore-hosts', original["ignore_hosts"]])
            else:
                cmds = [['gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'none']]
            for cmd in cmds:
                p = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                await p.communicate()
                if p.returncode != 0: return False
                
        state['proxy_backed_up'] = False
        state['proxy_enabled'] = original.get("enabled", False)
        state.pop("original_proxy", None)
        save_state(state)
        log("System proxy restored to original settings.", "PASS")
        return True
    except Exception as e:
        logger.error(f"Proxy restore error: {e}")
        return False

async def set_system_proxy(enable, port=None):
    if not port: port = LOCAL_HTTP_PORT
    system = platform.system().lower()
    state = load_state()
    
    if enable and not state.get('proxy_backed_up'):
        state['original_proxy'] = await get_current_proxy()
        if not state['original_proxy'].get("valid"):
            log("CRITICAL: Failed to backup original proxy state. Aborting.", "ERROR")
            return False
        state['proxy_backed_up'] = True
        save_state(state)
        
    try:
        if system == 'windows':
            import winreg
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, winreg.KEY_ALL_ACCESS)
                if enable:
                    winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, f'127.0.0.1:{port}')
                    winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, 'localhost;127.0.0.1;<local>')
                else:
                    winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
                ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0); ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
            except PermissionError:
                log("Permission denied when changing Windows proxy. Try running as Administrator.", "WARN")
                return False
        elif system == 'darwin':
            interface = await get_default_interface()
            if enable:
                p1 = await asyncio.create_subprocess_exec('networksetup', '-setwebproxy', interface, '127.0.0.1', str(port), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                await p1.communicate()
                p2 = await asyncio.create_subprocess_exec('networksetup', '-setsecurewebproxy', interface, '127.0.0.1', str(port), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                await p2.communicate()
                if p1.returncode != 0 or p2.returncode != 0: return False
            else:
                p1 = await asyncio.create_subprocess_exec('networksetup', '-setwebproxystate', interface, 'off', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                await p1.communicate()
                p2 = await asyncio.create_subprocess_exec('networksetup', '-setsecurewebproxystate', interface, 'off', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                await p2.communicate()
                if p1.returncode != 0 or p2.returncode != 0: return False
        else:
            if not shutil.which('gsettings'):
                log("gsettings not found. Cannot change system proxy on Linux.", "WARN")
                return False
            if enable:
                cmds = [
                    ['gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'manual'],
                    ['gsettings', 'set', 'org.gnome.system.proxy', 'host', '127.0.0.1'],
                    ['gsettings', 'set', 'org.gnome.system.proxy', 'port', str(port)],
                    ['gsettings', 'set', 'org.gnome.system.proxy.http', 'host', '127.0.0.1'],
                    ['gsettings', 'set', 'org.gnome.system.proxy.http', 'port', str(port)],
                    ['gsettings', 'set', 'org.gnome.system.proxy.https', 'host', '127.0.0.1'],
                    ['gsettings', 'set', 'org.gnome.system.proxy.https', 'port', str(port)],
                    ['gsettings', 'set', 'org.gnome.system.proxy.ftp', 'host', '127.0.0.1'],
                    ['gsettings', 'set', 'org.gnome.system.proxy.ftp', 'port', str(port)]
                ]
            else:
                cmds = [['gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'none']]
            for cmd in cmds:
                p = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                await p.communicate()
                if p.returncode != 0: return False
        
        state = load_state()
        state['proxy_enabled'] = enable
        save_state(state)
        return True
    except Exception as e:
        logger.error(f"Failed to set system proxy: {e}")
        return False

async def test_proxy_throughput(proxy_url, timeout=15):
    test_urls = ["https://speed.cloudflare.com/__down?bytes=5000000", "https://cp.cloudflare.com/generate_204"]
    for url in test_urls:
        try:
            start = time.time(); downloaded = 0; timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                async with session.get(url, proxy=proxy_url) as resp:
                    resp.raise_for_status()
                    async for chunk in resp.content.iter_chunked(65536):
                        downloaded += len(chunk)
                        if downloaded >= 2000000: break
            elapsed = time.time() - start
            if elapsed > 0 and downloaded > 10000: return (downloaded * 8 / 1000) / elapsed
        except Exception as e:
            logger.debug(f"Proxy throughput error: {e}")
            continue
    return 0

async def execute_bypass_and_connect(creds, all_configs=None, dpi_state='none'):
    global xray_proc, dnstt_proc, LOCAL_SOCKS_PORT, LOCAL_HTTP_PORT
    async with xray_lock:
        old_xray_proc = xray_proc if (xray_proc and xray_proc.returncode is None) else None
        old_dnstt_proc = dnstt_proc if (dnstt_proc and dnstt_proc.returncode is None) else None
        old_proxy_active = old_xray_proc is not None
        old_socks_port = LOCAL_SOCKS_PORT
        old_http_port = LOCAL_HTTP_PORT

        setup_dynamic_ports()

        log_tasks = []

        async def restore_state_on_failure():
            global xray_proc, dnstt_proc, LOCAL_SOCKS_PORT, LOCAL_HTTP_PORT
            for t in log_tasks:
                try: t.cancel()
                except Exception: pass
            log_tasks.clear()
            if xray_proc and xray_proc.returncode is None and xray_proc is not old_xray_proc:
                try:
                    xray_proc.terminate()
                    await asyncio.wait_for(xray_proc.wait(), timeout=3)
                except Exception:
                    try: xray_proc.kill()
                    except Exception as e: logger.error(f"Kill new xray error: {e}")
            if dnstt_proc and dnstt_proc.returncode is None and dnstt_proc is not old_dnstt_proc:
                try:
                    dnstt_proc.terminate()
                    await asyncio.wait_for(dnstt_proc.wait(), timeout=3)
                except Exception:
                    try: dnstt_proc.kill()
                    except Exception as e: logger.error(f"Kill new dnstt error: {e}")
            release_reserved_ports()

            if old_proxy_active:
                xray_proc = old_xray_proc
                dnstt_proc = old_dnstt_proc
                LOCAL_SOCKS_PORT = old_socks_port
                LOCAL_HTTP_PORT = old_http_port
            else:
                xray_proc = None
                dnstt_proc = None
                await restore_system_proxy()

        async def kill_old_processes_on_success():
            if old_xray_proc and old_xray_proc.returncode is None:
                try:
                    old_xray_proc.terminate()
                    await asyncio.wait_for(old_xray_proc.wait(), timeout=5)
                except Exception:
                    try: old_xray_proc.kill()
                    except Exception as e: logger.error(f"Kill old xray error: {e}")
            if old_dnstt_proc and old_dnstt_proc.returncode is None:
                try:
                    old_dnstt_proc.terminate()
                    await asyncio.wait_for(old_dnstt_proc.wait(), timeout=5)
                except Exception:
                    try: old_dnstt_proc.kill()
                    except Exception as e: logger.error(f"Kill old dnstt error: {e}")

        latency = await check_config_latency(creds)
        if latency is None and creds["protocol"] not in (
            "cloudflare_worker", "tor_snowflake", "warp", "warp_over_reality", "tor_proxy", "psiphon", "dnstt",
            "hysteria2", "hy2", "tuic"
        ):
            proto_prefix = get_proto_prefix(creds['protocol'])
            server_ip = creds.get(f"{proto_prefix}_server_ip")
            log(f"  -> Server {server_ip} is unreachable. Skipping...", "WARN")
            await restore_state_on_failure()
            return False

        config_file, binary_name = await generate_bypass_config(creds, all_configs, dpi_state)
        if not config_file:
            await restore_state_on_failure()
            return False

        binary_path = XRAY_BINARY_PATH
        if binary_name == "hysteria": binary_path = HYSTERIA_BINARY_PATH
        elif binary_name == "tor": binary_path = TOR_BINARY_PATH
        elif binary_name == "tuic": binary_path = TUIC_BINARY_PATH
        elif binary_name == "naive": binary_path = NAIVE_BINARY_PATH
        elif binary_name == "psiphon": binary_path = PSIPHON_BINARY_PATH
        elif binary_name == "xray+dnstt": binary_path = XRAY_BINARY_PATH
            
        if not binary_path or not os.path.isfile(binary_path):
            log(f"{binary_name} is not installed or not in PATH. Cannot auto-connect.", "FAIL")
            await restore_state_on_failure()
            return False

        abs_config_file = os.path.join(DATA_DIR, config_file) if not os.path.isabs(config_file) else config_file

        if binary_name == "xray" or binary_name == "xray+dnstt":
            await ensure_geo_files()
            log("  -> Running Xray config pre-flight test...", "INFO")
            test_proc = await asyncio.create_subprocess_exec(XRAY_BINARY_PATH, 'run', '-test', '-c', abs_config_file, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, stderr = await asyncio.wait_for(test_proc.communicate(), timeout=10)
                if test_proc.returncode != 0:
                    err = stderr.decode(errors='ignore')
                    out = stdout.decode(errors='ignore')
                    log(f"  -> Pre-flight test failed! Syntax/Config error:\nOUT: {out}\nERR: {err}", "ERROR")
                    await restore_state_on_failure()
                    return False
            except asyncio.TimeoutError:
                test_proc.kill()
                log("  -> Pre-flight test timed out.", "WARN")
                await restore_state_on_failure()
                return False

        if binary_name == "tor": cmd_args = [binary_path, '-f', abs_config_file]
        elif binary_name == "hysteria": cmd_args = [binary_path, 'client', '-c', abs_config_file]
        elif binary_name == "tuic": cmd_args = [binary_path, '-c', abs_config_file]
        elif binary_name == "naive": cmd_args = [binary_path, abs_config_file]
        elif binary_name == "psiphon": cmd_args = [binary_path, '-config', abs_config_file]
        else: cmd_args = [binary_path, 'run', '-c', abs_config_file]

        try:
            release_reserved_ports()
            
            if binary_name == "xray+dnstt":
                if not DNTT_BINARY_PATH or not os.path.isfile(DNTT_BINARY_PATH):
                    log("dnstt-client is not installed or not in PATH. Cannot auto-connect.", "FAIL")
                    await restore_state_on_failure()
                    return False
                    
                local_port = creds.get("dnstt_local_port")
                domain = creds.get("dnstt_domain")
                pubkey = creds.get("dnstt_pubkey")
                dnstt_args = [DNTT_BINARY_PATH, '-u', pubkey, domain, f"127.0.0.1:{local_port}"]
                new_dnstt = await asyncio.create_subprocess_exec(*dnstt_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                dnstt_proc = new_dnstt
                
                async def tail_dnstt_logs(stream, prefix):
                    while True:
                        line = await stream.readline()
                        if not line: break
                        decoded_line = line.decode(errors='ignore').strip()
                        if not decoded_line: continue
                        if "error" in decoded_line.lower() or "warn" in decoded_line.lower():
                            log(f"[dnstt] {prefix}: {decoded_line}", "INFO")
                            
                log_tasks.append(asyncio.create_task(tail_dnstt_logs(new_dnstt.stdout, "STDOUT")))
                log_tasks.append(asyncio.create_task(tail_dnstt_logs(new_dnstt.stderr, "STDERR")))
                await asyncio.sleep(2)

            if creds["protocol"] == "tor_proxy":
                proc = await asyncio.create_subprocess_exec(*cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                xray_proc = proc
            else:
                xray_proc = await asyncio.create_subprocess_exec(*cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                proc = xray_proc
            
            async def tail_logs(stream, prefix):
                important_keywords = ["error", "warn", "rejected", "failed to", "i/o timeout", "invalid", "fatal", "panic"]
                while True:
                    line = await stream.readline()
                    if not line: break
                    decoded_line = line.decode(errors='ignore').strip()
                    if not decoded_line:
                        continue
                    if "udp:169.254" in decoded_line or "udp:192.168." in decoded_line:
                        if ":137 " in decoded_line or ":138 " in decoded_line or ":5353 " in decoded_line: continue
                    if any(keyword in decoded_line.lower() for keyword in important_keywords):
                        log(f"[{binary_name}] {prefix}: {decoded_line}", "INFO")
            
            log_tasks.append(asyncio.create_task(tail_logs(proc.stdout, "STDOUT")))
            log_tasks.append(asyncio.create_task(tail_logs(proc.stderr, "STDERR")))
            
            required_ports = [LOCAL_HTTP_PORT]
            if binary_name != "naive":
                required_ports.append(LOCAL_SOCKS_PORT)
                
            all_ports_ready = True
            for check_port in required_ports:
                port_ok = False
                for _ in range(10):
                    try:
                        reader, writer = await asyncio.open_connection("127.0.0.1", check_port)
                        writer.close(); await writer.wait_closed()
                        port_ok = True; break
                    except Exception:
                        if proc.returncode is not None: break
                        await asyncio.sleep(1)
                if not port_ok:
                    all_ports_ready = False
                    break
            
            if not all_ports_ready:
                if proc.returncode is not None: log(f"{binary_name} crashed or failed to bind port! See logs above.", "ERROR")
                else: log(f"{binary_name} started but not all required ports are listening.", "ERROR")
                await restore_state_on_failure()
                return False

            await asyncio.sleep(3)
            
            proxy = f"http://127.0.0.1:{LOCAL_HTTP_PORT}"

            if binary_name == "tor":
                log(f"Tor process is running. Waiting for circuit to establish (up to 90s)...", "INFO")
                for _ in range(30):
                    if proc.returncode is not None:
                        log(f"Tor crashed during circuit building!", "ERROR")
                        await restore_state_on_failure()
                        return False
                    try:
                        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as s:
                            async with s.get("https://cp.cloudflare.com/generate_204", proxy=proxy) as r:
                                if r.status in [204, 200]:
                                    log(f"Tor circuit established successfully! Connected via Tor.", "PASS")
                                    if not await set_system_proxy(True, LOCAL_HTTP_PORT):
                                        log("Failed to set system proxy. Aborting Tor connection.", "FAIL")
                                        await restore_state_on_failure()
                                        return False

                                    await kill_old_processes_on_success()
                                    return True
                    except Exception as e:
                        logger.debug(f"Tor check error: {e}")
                    await asyncio.sleep(3)
                
                log("Tor failed to build a circuit within 90 seconds.", "FAIL")
                await restore_state_on_failure()
                return False

            proxy_timeout = 30 if binary_name in ["psiphon", "xray+dnstt"] else (20 if dpi_state in ['rst', 'drop', 'aggressive'] else 10)
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=proxy_timeout)) as session:
                success = False
                test_urls = ["https://cp.cloudflare.com/generate_204", "https://www.google.com/generate_204", "https://cloudflare.com/cdn-cgi/trace"]
                for url in test_urls:
                    if proc.returncode is not None:
                        log(f"Proxy core crashed during test! See logs above.", "ERROR")
                        await restore_state_on_failure()
                        return False
                    try:
                        async with session.get(url, proxy=proxy) as resp:
                            if resp.status in [204, 200, 301, 302]:
                                text_check = ""
                                if "trace" in url:
                                    text_check = await resp.text()
                                    if "ip=" not in text_check: raise Exception("Trace validation failed")
                                
                                latency_str = f"{latency}ms" if latency else "N/A"
                                log(f"Successfully connected via {creds['protocol'].upper()}! (Latency: {latency_str})", "PASS")
                                
                                log("  -> Testing throughput...", "INFO")
                                speed = await test_proxy_throughput(proxy)
                                
                                if speed > 0:
                                    log(f"  -> Throughput: {speed:.0f} Kbps ({speed/125:.1f} MB/s)", "PASS")
                                    if speed < 20:
                                        log("  -> Speed too low. Trying next config...", "WARN")
                                        await restore_state_on_failure()
                                        return False
                                else: 
                                    log("  -> Throughput test failed. Trying next config...", "WARN")
                                    await restore_state_on_failure()
                                    return False
                                
                                if not await set_system_proxy(True, LOCAL_HTTP_PORT):
                                    log("Failed to set system proxy. Aborting connection.", "FAIL")
                                    await restore_state_on_failure()
                                    return False
                                
                                await kill_old_processes_on_success()
                                
                                if creds.get("raw_link"): save_working_config(creds["raw_link"])
                                success = True; break
                    except aiohttp.ClientProxyConnectionError:
                        log(f"  -> Proxy connection refused on port {LOCAL_HTTP_PORT}.", "WARN"); continue
                    except aiohttp.ClientConnectorError:
                        log(f"  -> Proxy dropped connection (Outbound server unreachable/blocked or UDP issue).", "WARN"); continue
                    except (aiohttp.ServerDisconnectedError, ssl.SSLError) as e:
                        logger.debug(f"Proxy SSL/Disc error: {e}")
                        log(f"  -> Proxy dropped connection or SSL error.", "WARN"); continue
                    except asyncio.TimeoutError:
                        log(f"  -> URL {url} timed out via proxy.", "WARN"); continue
                    except Exception as e:
                        logger.warning(f"URL {url} failed via proxy: {type(e).__name__} - {e}")
                        log(f"  -> URL {url} failed via proxy: {type(e).__name__}", "WARN"); continue
                if not success:
                    log(f"Proxy failed to connect to test URLs or validation failed.", "FAIL")
                    if creds.get("raw_link"): remove_working_config(creds["raw_link"])
                    await restore_state_on_failure()
                    return False
                return True
        except Exception as e:
            log(f"Failed to start {binary_name}: {e}", "ERROR")
            if 'proc' in locals() and proc and proc.returncode is None and proc is not old_xray_proc:
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=3)
                except:
                    try: proc.kill()
                    except: pass
            for t in log_tasks:
                try: t.cancel()
                except Exception: pass
            await restore_state_on_failure()
            return False

def generate_network_report(states, applied_bypass="none", diagnosis=None, selected_method=None):
    if not diagnosis: diagnosis = []
    if not selected_method: selected_method = "unknown"
    
    confidence = "low"
    if selected_method == "healthy":
        confidence = "high"
    elif selected_method in ["tor_proxy", "tor_snowflake", "psiphon", "dnstt"]:
        confidence = "medium"
    elif selected_method in ["vless", "trojan", "hysteria2", "hy2", "tuic", "warp", "cf_worker", "balancer"]:
        if "undetermined" in diagnosis or any(v == 'unknown' for v in states.values() if isinstance(v, str)):
            confidence = "medium"
        else:
            confidence = "high"
            
    verdict = {
        "diagnosis": diagnosis,
        "selected_method": selected_method,
        "confidence": confidence
    }
    report = {"timestamp": datetime.datetime.now().isoformat(), "network_states": states, "applied_bypass": applied_bypass, "verdict": verdict}
    try: atomic_write_json(REPORT_FILE, report)
    except Exception as e: logger.error(f"Report write failed: {e}")

async def check_captive_portal():
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.get(CONFIG["targets"]["captive_portal_url"]) as resp:
                text = await resp.text()
                return "success" not in text
    except Exception as e:
        logger.debug(f"Captive portal check error: {e}")
        return False

async def test_current_proxy_health():
    if not xray_proc or xray_proc.returncode is not None:
        return False
    proxy_url = f"http://127.0.0.1:{LOCAL_HTTP_PORT}"
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
            async with s.get("https://cp.cloudflare.com/generate_204", proxy=proxy_url) as r:
                return r.status in [204, 200]
    except Exception:
        return False

async def decision_engine(states):
    log("Comprehensive Network Analysis & Action Report:", "HEADER")
    issues = []
    diagnosis = []

    if await check_direct_health():
        log("Network is healthy (Direct access succeeded). No bypass needed.", "PASS")
        diagnosis.append("healthy")
        generate_network_report(states, "healthy_no_bypass", diagnosis, "healthy")
        global xray_proc, dnstt_proc
        async with xray_lock:
            if xray_proc and xray_proc.returncode is None:
                log("Stopping bypass engine as network is healthy...", "INFO")
                try:
                    xray_proc.terminate(); await asyncio.wait_for(xray_proc.wait(), timeout=5)
                except Exception:
                    try: xray_proc.kill()
                    except Exception as e: logger.error(f"Kill error: {e}")
                xray_proc = None
                await restore_system_proxy()
            if dnstt_proc and dnstt_proc.returncode is None:
                try:
                    dnstt_proc.terminate(); await asyncio.wait_for(dnstt_proc.wait(), timeout=5)
                except Exception:
                    try: dnstt_proc.kill()
                    except Exception as e: logger.error(f"Kill error: {e}")
                dnstt_proc = None
                
        state = load_state()
        if state.get('dns_changed'):
            await restore_system_dns()

        state = load_state()
        state['cdn_204_failures'] = 0
        save_state(state)
            
        await fetch_fresh_configs(wait=False)
        return 0

    if await check_captive_portal():
        log("Captive Portal detected! Network tests may be misleading.", "WARN")
        issues.append(("Captive Portal Detected", ["Authenticate in your browser first."]))
        diagnosis.append("captive_portal")
        generate_network_report(states, "captive_portal_no_action", diagnosis, "captive_portal")
        for idx, (issue, solutions) in enumerate(issues, 1):
            log(f"Issue {idx}: {issue}", "FAIL")
            for sol in solutions: log(f"   - {sol}", "SOL")
        log("Pausing bypass attempts until network is authenticated.", "WARN")
        return 120

    if not states['ip']['internal'] and not states['ip']['external']:
        issues.append(("Total Internet Blackout", ["Wait for reconnection."]))
        diagnosis.append("blackout")
        generate_network_report(states, "blackout_no_action", diagnosis, "blackout")
        return 120

    if states['ip']['internal'] and not states['ip']['external']:
        issues.append(("Complete International Transit Cut (National Internet Only)", 
                       ["International traffic is completely blocked. VPN/Bypass methods will not work.", 
                        "Please wait for restoration or use eSIM/Satellite."]))
        diagnosis.append("intl_transit_cut")
        generate_network_report(states, "intl_transit_cut", diagnosis, "intl_transit_cut")
        for idx, (issue, solutions) in enumerate(issues, 1):
            log(f"Issue {idx}: {issue}", "FAIL")
            for sol in solutions: log(f"   - {sol}", "SOL")
        return 300 

    if states.get('speed') == 'throttled_intl':
        issues.append(("Severe International Throttling", ["Switch to UDP protocols."]))
        diagnosis.append("throttling")
    elif states.get('speed') in ['failed', 'slow']:
        issues.append(("Speed Issue Detected (Slow or Failed)", ["Check routing or try UDP protocols."]))
        diagnosis.append("degradation")
        
    if states.get('vpn') == 'blocked':
        issues.append(("VPN Ports Blocked", ["Use protocols on port 443 or 80."]))
        diagnosis.append("vpn_blocked")
    elif states.get('vpn') == 'partial':
        issues.append(("Some VPN Ports Blocked", ["Ensure protocols use open ports like 443."]))
        diagnosis.append("vpn_partial")
        
    if states.get('dns') in ['dropped', 'hijacked']:
        issues.append(("DNS Disruption", ["Use encrypted DNS (DoH/DoT)."]))
        diagnosis.append(states.get('dns'))
        await apply_system_dns()
    elif states.get('dns') == 'doh_only':
        issues.append(("UDP DNS Blocked", ["Use DoH-only configs."]))
        diagnosis.append("udp_dropped")
    elif states.get('dns') == 'system_broken':
        issues.append(("System DNS Broken (Cannot resolve domains)", 
                       ["System DNS will be fixed automatically."]))
        diagnosis.append("system_broken")
        await apply_system_dns()
    
    if states.get('dpi') in ['rst', 'drop', 'aggressive']:
        issues.append(("Deep Packet Inspection (SNI Filtering)", ["Use XTLS-Reality, NaiveProxy, or Fragmentation."]))
        diagnosis.append(states.get('dpi'))
    elif states.get('dpi') == 'timeout':
        issues.append(("Network Instability", ["Retry connection."]))
        diagnosis.append("timeout")
        
    if states.get('udp') == 'dropped':
        issues.append(("UDP Traffic Dropped", ["Avoid Hysteria2/TUIC/WARP. Use TCP protocols."]))
        diagnosis.append("udp_dropped")

    if not issues:
        dns_state = states.get('dns')
        dpi_state = states.get('dpi')
        speed_state = states.get('speed')
        
        vpn_state = states.get('vpn')
        udp_state = states.get('udp')
        quic_state = states.get('quic')
        
        critical_ok = (
            dns_state in ['ok', 'doh_only', 'system_broken'] and 
            dpi_state in ['none', 'ok'] and 
            speed_state in ['ok', 'slow']
        )
        non_critical_tolerable = all(
            s in ['ok', 'reachable', 'none', 'healthy', 'unknown', 'partial'] 
            for s in [vpn_state, udp_state, quic_state]
        )
        
        if critical_ok and non_critical_tolerable:
            log("Network is healthy.", "PASS")
            diagnosis.append("healthy")
            generate_network_report(states, "healthy_no_bypass", diagnosis, "healthy")
            async with xray_lock:
                if xray_proc and xray_proc.returncode is None:
                    log("Stopping bypass engine as network is healthy...", "INFO")
                    try:
                        xray_proc.terminate(); await asyncio.wait_for(xray_proc.wait(), timeout=5)
                    except Exception:
                        try: xray_proc.kill()
                        except Exception as e: logger.error(f"Kill error: {e}")
                    xray_proc = None
                    await restore_system_proxy()
                if dnstt_proc and dnstt_proc.returncode is None:
                    try:
                        dnstt_proc.terminate(); await asyncio.wait_for(dnstt_proc.wait(), timeout=5)
                    except Exception:
                        try: dnstt_proc.kill()
                        except Exception as e: logger.error(f"Kill error: {e}")
                    dnstt_proc = None
                    
            state = load_state()
            if state.get('dns_changed'):
                await restore_system_dns()
            state = load_state()
            state['cdn_204_failures'] = 0
            save_state(state)
                
            await fetch_fresh_configs(wait=False)
            return 0
        else:
            issues.append(("Undetermined Network State", ["Network status is unknown. Proceeding with caution."]))
            diagnosis.append("undetermined")

    for idx, (issue, solutions) in enumerate(issues, 1):
        log(f"Issue {idx}: {issue}", "FAIL")
        for sol in solutions: log(f"   - {sol}", "SOL")

    log("Activating Automated Bypass Engine...", "SOL")
    unified_cfg = load_unified_config()
    config_links = load_working_configs()
    if not config_links:
        cached_configs = load_cached_configs()
        config_links = unified_cfg.get("configs", [])
        if not config_links and cached_configs: config_links = cached_configs

    if not config_links:
        sub_urls = unified_cfg.get("subscription_urls", [])
        if sub_urls:
            sub_configs = await fetch_subscription_configs(sub_urls)
            if sub_configs: config_links = sub_configs

    parsed_configs = []
    for link in config_links:
        try:
            parsed_configs.append(parse_config_link(link))
        except Exception:
            pass
    parsed_configs = [c for c in parsed_configs if c["protocol"] != "unsupported"]

    dpi_state = states.get('dpi')
    udp_state = states.get('udp')
    quic_state = states.get('quic')

    valid_configs = []
    if parsed_configs:
        log("  -> Testing latency for all available configs...", "INFO")
        try:
            async def test_all_configs():
                nonlocal valid_configs
                latencies = await asyncio.gather(*[check_config_latency(c) for c in parsed_configs], return_exceptions=True)
                
                filtered_configs = []
                for c, lat in zip(parsed_configs, latencies):
                    if isinstance(lat, Exception) or lat is None: continue
                    filtered_configs.append((c, lat))
                
                valid_configs = filtered_configs
                valid_configs.sort(key=lambda x: x[1] if isinstance(x[1], (int, float)) else 9999)
                
            await asyncio.wait_for(test_all_configs(), timeout=CONFIG["intervals"]["global_test_timeout"])
        except asyncio.TimeoutError:
            log("  -> Config testing timed out. Proceeding with partial results.", "WARN")

    preferred_configs = []
    if dpi_state == 'aggressive' or dpi_state in ['rst', 'drop']:
        preferred_configs = [c for c, lat in valid_configs if c["protocol"] == "vless" and c.get("vless_security") == "reality"]
        preferred_configs += [c for c, lat in valid_configs if c["protocol"] in ("naive", "naive+https")]
        preferred_configs += [c for c, lat in valid_configs if c["protocol"] == "trojan"]
        preferred_configs += [c for c, lat in valid_configs if c["protocol"] == "shadowtls"]
        if quic_state == 'reachable': preferred_configs += [c for c, lat in valid_configs if c["protocol"] in ("hysteria2", "hy2", "tuic")]
    elif udp_state == 'dropped' or quic_state == 'dropped' or udp_state == 'unknown':
        preferred_configs = [c for c, lat in valid_configs if c["protocol"] in ["vless", "trojan", "shadowtls", "naive", "naive+https"]]
    else:
        preferred_configs = [c for c, lat in valid_configs if c["protocol"] in ("hysteria2", "hy2", "tuic")]
        preferred_configs += [c for c, lat in valid_configs if c["protocol"] in ["vless", "trojan", "shadowtls"]]
    
    if not preferred_configs: preferred_configs = [c for c, lat in valid_configs]

    tcp_configs_for_balancer = [c for c, lat in valid_configs if c["protocol"] in ["vless", "trojan", "shadowtls"]][:5]

    protocol_attempts = {}; MAX_ATTEMPTS_PER_PROTOCOL = 5

    worker_data = unified_cfg.get("cloudflare_worker")
    if worker_data and states.get('dpi') in ['aggressive', 'rst', 'drop']:
        log("  -> DPI detected. Prioritizing Cloudflare Workers (WARP-WS)...", "SOL")
        await asyncio.sleep(random.uniform(2.0, 5.0))
        if await execute_bypass_and_connect({"protocol": "cloudflare_worker", "worker_data": worker_data}, dpi_state=dpi_state):
            generate_network_report(states, "connected_via_cf_worker", diagnosis, "cf_worker")
            state = load_state(); state['cdn_204_failures'] = 0; save_state(state)
            await fetch_fresh_configs(wait=False); return 0

    if preferred_configs:
        if len(tcp_configs_for_balancer) >= 2 and (states.get('udp') == 'dropped' or states.get('speed') == 'throttled_intl' or states.get('dpi') in ['aggressive', 'rst']):
            log(f"  -> Attempting Balancer connection with {len(tcp_configs_for_balancer)} TCP configs...", "SOL")
            await asyncio.sleep(random.uniform(2.0, 5.0))
            if await execute_bypass_and_connect(tcp_configs_for_balancer[0], all_configs=tcp_configs_for_balancer, dpi_state=dpi_state):
                generate_network_report(states, "connected_via_balancer", diagnosis, "balancer")
                state = load_state(); state['cdn_204_failures'] = 0; save_state(state)
                await fetch_fresh_configs(wait=False); return 0

        cache_cleared = not load_cached_configs()
        for c in preferred_configs:
            proto = c['protocol']; protocol_attempts[proto] = protocol_attempts.get(proto, 0) + 1
            if protocol_attempts[proto] > MAX_ATTEMPTS_PER_PROTOCOL: continue
            log(f"  -> Attempting connection with: {proto.upper()} (Attempt {protocol_attempts[proto]}/{MAX_ATTEMPTS_PER_PROTOCOL})", "SOL")
            await asyncio.sleep(random.uniform(2.0, 5.0))
            if await execute_bypass_and_connect(c, dpi_state=dpi_state):
                generate_network_report(states, f"connected_via_{proto}", diagnosis, proto)
                state = load_state(); state['cdn_204_failures'] = 0; save_state(state)
                await fetch_fresh_configs(wait=False); return 0
            else:
                wait_time = 2 ** (protocol_attempts[proto] - 1)
                log(f"  -> Waiting {wait_time} seconds (Exponential Backoff)...", "INFO")
                await asyncio.sleep(wait_time)
                if not cache_cleared: clear_cached_configs(); cache_cleared = True

    warp_udp = await test_warp_udp_reachability()
    if udp_state != 'dropped' and warp_udp != 'dropped':
        warp_data = unified_cfg.get("warp")
        if warp_data:
            log(f"  -> Using WARP from cnfg.json... (WARP UDP: {warp_udp})", "SOL")
            await asyncio.sleep(random.uniform(2.0, 5.0))
            if await execute_bypass_and_connect({"protocol": "warp", "warp_data": warp_data}, dpi_state=dpi_state):
                generate_network_report(states, "connected_via_warp", diagnosis, "warp")
                state = load_state(); state['cdn_204_failures'] = 0; save_state(state)
                await fetch_fresh_configs(wait=False); return 0
            log("  -> Default WARP failed. Trying alternative ports (853, 4500, 500)...", "SOL")
            alt_endpoints = ["162.159.193.1:853", "162.159.193.1:4500", "188.114.96.1:853", "188.114.96.1:500"]
            for ep in alt_endpoints:
                log(f"  -> Retrying WARP with Endpoint: {ep}", "SOL")
                await asyncio.sleep(random.uniform(2.0, 5.0))
                if await execute_bypass_and_connect({"protocol": "warp", "warp_data": warp_data, "custom_endpoint": ep}, dpi_state=dpi_state):
                    generate_network_report(states, "connected_via_warp_alt_endpoint", diagnosis, "warp_alt_endpoint")
                    state = load_state(); state['cdn_204_failures'] = 0; save_state(state)
                    await fetch_fresh_configs(wait=False); return 0
            log("  -> Default WARP IPs blocked. Scanning for UDP-reachable WARP IPs...", "SOL")
            clean_endpoints = await scan_udp_reachability()
            for cip, cport in clean_endpoints:
                log(f"  -> Retrying WARP with Dynamic IP: {cip}:{cport}", "SOL")
                await asyncio.sleep(random.uniform(2.0, 5.0))
                if await execute_bypass_and_connect({"protocol": "warp", "warp_data": warp_data, "custom_endpoint": f"{cip}:{cport}"}, dpi_state=dpi_state):
                    generate_network_report(states, "connected_via_warp_dynamic_ip", diagnosis, "warp_dynamic_ip")
                    state = load_state(); state['cdn_204_failures'] = 0; save_state(state)
                    await fetch_fresh_configs(wait=False); return 0
            log("  -> WARP likely blocked by DPI. Attempting WARP over VLESS-Reality encapsulation...", "SOL")
            reality_cfg = next((c for c, lat in valid_configs if c["protocol"] == "vless" and c.get("vless_security") == "reality"), None)
            if reality_cfg:
                await asyncio.sleep(random.uniform(2.0, 5.0))
                if await execute_bypass_and_connect({"protocol": "warp_over_reality", "warp_data": warp_data, "reality_config": reality_cfg}, dpi_state=dpi_state):
                    generate_network_report(states, "connected_via_warp_over_reality", diagnosis, "warp_over_reality")
                    state = load_state(); state['cdn_204_failures'] = 0; save_state(state)
                    await fetch_fresh_configs(wait=False); return 0
            else: log("  -> No VLESS-Reality config available to tunnel WARP.", "WARN")
    else: log("  -> Skipping WARP fallback because UDP traffic is dropped.", "WARN")

    if worker_data:
        log("  -> Using Cloudflare Workers (WARP-WS) from cnfg.json...", "SOL")
        await asyncio.sleep(random.uniform(2.0, 5.0))
        if await execute_bypass_and_connect({"protocol": "cloudflare_worker", "worker_data": worker_data}, dpi_state=dpi_state):
            generate_network_report(states, "connected_via_cf_worker", diagnosis, "cf_worker")
            state = load_state(); state['cdn_204_failures'] = 0; save_state(state)
            await fetch_fresh_configs(wait=False); return 0

    psiphon_data = unified_cfg.get("psiphon")
    if psiphon_data is not None:
        log("  -> Trying Psiphon Network...", "SOL")
        await asyncio.sleep(random.uniform(2.0, 5.0))
        if await execute_bypass_and_connect({"protocol": "psiphon"}, dpi_state=dpi_state):
            generate_network_report(states, "connected_via_psiphon", diagnosis, "psiphon")
            state = load_state(); state['cdn_204_failures'] = 0; save_state(state)
            await fetch_fresh_configs(wait=False); return 0

    dnstt_data = unified_cfg.get("dnstt")
    if dnstt_data and dnstt_data.get("domain") and dnstt_data.get("pubkey"):
        log("  -> Trying Dnstt Tunnel...", "SOL")
        await asyncio.sleep(random.uniform(2.0, 5.0))
        if await execute_bypass_and_connect({"protocol": "dnstt", "dnstt_domain": dnstt_data["domain"], "dnstt_pubkey": dnstt_data["pubkey"]}, dpi_state=dpi_state):
            generate_network_report(states, "connected_via_dnstt", diagnosis, "dnstt")
            state = load_state(); state['cdn_204_failures'] = 0; save_state(state)
            await fetch_fresh_configs(wait=False); return 0

    log("  -> Trying Tor Network (Direct Tor Proxy)...", "SOL")
    await asyncio.sleep(random.uniform(2.0, 5.0))
    if await execute_bypass_and_connect({"protocol": "tor_proxy"}, dpi_state=dpi_state):
        generate_network_report(states, "connected_via_tor_proxy", diagnosis, "tor_proxy")
        state = load_state(); state['cdn_204_failures'] = 0; save_state(state)
        await fetch_fresh_configs(wait=False); return 0

    log("  -> Using Tor Network (Snowflake/obfs4)...", "SOL")
    await asyncio.sleep(random.uniform(2.0, 5.0))
    if await execute_bypass_and_connect({"protocol": "tor_snowflake"}, dpi_state=dpi_state):
        generate_network_report(states, "connected_via_tor", diagnosis, "tor_snowflake")
        state = load_state(); state['cdn_204_failures'] = 0; save_state(state)
        await fetch_fresh_configs(wait=False); return 0

    log("  -> All bypass methods failed. Attempting to fetch fresh configs...", "FAIL")
    selected_method = "all_failed"
    old_hash = hashlib.md5(json.dumps(unified_cfg, sort_keys=True).encode()).hexdigest()
    if await fetch_fresh_configs(wait=True):
        new_cfg = load_unified_config()
        new_hash = hashlib.md5(json.dumps(new_cfg, sort_keys=True).encode()).hexdigest()
        if new_hash != old_hash:
            log(f"  -> Configs updated by cnfg. Retrying in 15 seconds...", "SOL")
            generate_network_report(states, "failed_but_refreshed", diagnosis, selected_method); return 15
        else:
            log("  -> cnfg ran but configs are identical. Waiting 1 minute before retry...", "WARN")
            generate_network_report(states, "failed_cnfg_no_new_configs", diagnosis, selected_method); return 60

    generate_network_report(states, "all_bypasses_failed", diagnosis, selected_method)
    return 120

def get_state(result, default='unknown'):
    return default if isinstance(result, Exception) else result

async def main():
    current_year = datetime.datetime.now().year
    if current_year < 2025:
        log(f"CRITICAL: System time is set to {current_year}. This will cause SSL/TLS certificate errors and proxy failures!", "ERROR")

    acquire_lock()
    setup_signal_handlers()
    kill_stale_processes()
    check_dependencies()
    
    async def safe_restore(coro_func, name):
        for attempt in range(3):
            try:
                if await coro_func():
                    return True
            except Exception as e:
                logger.error(f"Exception during {name} restore: {e}")
            log(f"{name} restore failed (attempt {attempt+1}/3). Retrying in 5s...", "WARN")
            await asyncio.sleep(5)
        
        log(f"WARNING: Failed to restore {name} state after 3 attempts. Clearing state to allow execution.", "WARN")
        state = load_state()
        if name == "proxy":
            state['proxy_backed_up'] = False
            state['proxy_enabled'] = False
        elif name == "DNS":
            state['dns_backed_up'] = False
            state['dns_changed'] = False
        save_state(state)
        return True

    log("Performing startup recovery policy...", "SOL")
    state = load_state()
    if state.get('proxy_backed_up') or state.get('proxy_enabled'):
        log("Detected interrupted previous session. Restoring stale proxy state...", "WARN")
        if not await safe_restore(restore_system_proxy, "proxy"):
            sys.exit(1)
    if state.get('dns_backed_up') or state.get('dns_changed'):
        log("Detected interrupted previous session. Restoring stale DNS state...", "WARN")
        if not await safe_restore(restore_system_dns, "DNS"):
            sys.exit(1)

    log("Backing up current system proxy and DNS settings...", "SOL")
    proxy_data = await get_current_proxy()
    if not proxy_data.get("valid"):
        log("CRITICAL: Cannot determine current proxy state. Aborting to prevent state loss.", "ERROR")
        sys.exit(1)
        
    state = {}
    state['original_proxy'] = proxy_data
    state['proxy_backed_up'] = True
    state['original_dns'] = await get_current_dns()
    state['dns_backed_up'] = True
    state['cdn_204_failures'] = 0
    state['last_deep_scan'] = 0
    save_state(state)
    
    log("Disabling proxy temporarily for clean tests...", "SOL")
    if not await set_system_proxy(False):
        log("CRITICAL: Failed to disable system proxy for clean tests. Aborting.", "ERROR")
        sys.exit(1)
    
    if is_root_or_admin(): log("Admin/Root access detected.", "INFO")
    else: log("No Admin/Root access. System DNS & TUN mode won't work.", "WARN")
    print(f"{Colors.BOLD}Advanced Analyzer & Auto-Bypass Engine Started.{Colors.ENDC}\n")

    if not os.path.exists(UNIFIED_CONFIG_FILE) or os.path.getsize(UNIFIED_CONFIG_FILE) < 30:
        log("No valid cnfg.json found. Running cnfg...", "SOL")
        await fetch_fresh_configs(wait=True)
    else:
        await prompt_and_fetch_custom_configs()

    custom_sleep = 0
    while True:
        try:
            log("==================================================", "HEADER")
            if not await check_geolocation():
                custom_sleep = CONFIG["intervals"]["test_loop"]
                await asyncio.sleep(custom_sleep + random.uniform(0, 15)); continue

            if xray_proc and xray_proc.returncode is None:
                if await test_current_proxy_health():
                    state = load_state()
                    state['cdn_204_failures'] = 0
                    save_state(state)
                    log("Current proxy is healthy. Idle state - skipping all tests.", "PASS")
                    custom_sleep = CONFIG["intervals"]["test_loop"]
                    await asyncio.sleep(custom_sleep + random.uniform(0, 15))
                    continue
                else:
                    state = load_state()
                    failures = state.get('cdn_204_failures', 0) + 1
                    state['cdn_204_failures'] = failures
                    save_state(state)
                    log(f"Current proxy failed health check ({failures}/2 consecutive failures).", "WARN")
                    if failures < 2:
                        await asyncio.sleep(30 + random.uniform(0, 15))
                        continue
                    log("Two consecutive failures detected. Proceeding with deep scan.", "WARN")

            state = load_state()
            last_deep_scan = state.get('last_deep_scan', 0)
            cdn_failures = state.get('cdn_204_failures', 0)
            deep_scan_needed = (time.time() - last_deep_scan) >= DEEP_SCAN_INTERVAL or cdn_failures >= 2

            if await check_direct_health():
                log("Network is healthy. Skipping detailed tests.", "PASS")
                states = {
                    'ip': {'internal': True, 'external': True, 'icmp': True, 'tcp_ping': True, 'ipv6': 'ok'},
                    'dns': 'ok', 'vpn': 'ok', 'udp': 'ok', 'quic': 'reachable', 'dpi': 'none', 'speed': 'ok'
                }
                generate_network_report(states, "healthy_no_bypass", ["healthy"], "healthy")
                
                state = load_state()
                if state.get('dns_changed'):
                    await restore_system_dns()
                state = load_state()
                state['cdn_204_failures'] = 0
                save_state(state)
                    
                await fetch_fresh_configs(wait=False)
                custom_sleep = CONFIG["intervals"]["test_loop"]
                await asyncio.sleep(custom_sleep + random.uniform(0, 15))
                continue

            ip_s = await test_ip_layer()
            if not ip_s['internal'] and not ip_s['external']:
                log("Total Internet Blackout detected!", "FAIL")
                states = {'ip': ip_s, 'dns': 'failed', 'vpn': 'unknown', 'udp': 'unknown', 'quic': 'unknown', 'dpi': 'unknown', 'speed': 'failed'}
                generate_network_report(states, "blackout")
                custom_sleep = CONFIG["intervals"]["blackout_loop"]
                await asyncio.sleep(custom_sleep + random.uniform(0, 30)); continue

            if ip_s['external'] or ip_s['internal']:
                if deep_scan_needed:
                    dns_s = get_state(await test_dns_layer(), 'failed')
                    vpn_s = get_state(await test_vpn_ports(), 'unknown')
                    dpi_s = get_state(await test_dpi_layer(), 'unknown')
                    state = load_state()
                    state['last_deep_scan'] = time.time()
                    state['cached_dns_state'] = dns_s
                    state['cached_dpi_state'] = dpi_s
                    save_state(state)
                    log(f"  -> Deep scan completed. DNS: {dns_s}, DPI: {dpi_s}", "INFO")
                else:
                    state = load_state()
                    dns_s = state.get('cached_dns_state', 'unknown')
                    dpi_s = state.get('cached_dpi_state', 'unknown')
                    log(f"  -> Deep scan throttled (last scan < 1h ago & no consecutive CDN 204 failures). Using cached DNS ({dns_s}) and DPI ({dpi_s}).", "INFO")
                udp_s = get_state(await test_udp_status(), 'unknown')
                quic_s = get_state(await test_udp_443_probe(), 'unknown')
                speed_s = get_state(await test_throttling(), 'failed')
            else:
                dns_s, vpn_s, udp_s, quic_s, dpi_s, speed_s = 'failed', 'failed', 'failed', 'failed', 'unknown', 'failed'

            custom_sleep = await decision_engine({'ip': ip_s, 'dns': dns_s, 'vpn': vpn_s, 'udp': udp_s, 'quic': quic_s, 'dpi': dpi_s, 'speed': speed_s})

            if custom_sleep == 0:
                state = load_state()
                state['cdn_204_failures'] = 0
                save_state(state)

            sleep_time = custom_sleep if custom_sleep > 0 else CONFIG["intervals"]["test_loop"]
            await asyncio.sleep(sleep_time + random.uniform(0, 15))

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Engine crashed: {e}")
            try:
                if xray_proc and xray_proc.returncode is None:
                    xray_proc.terminate()
                    await asyncio.wait_for(xray_proc.wait(), timeout=5)
            except:
                try: xray_proc.kill()
                except: pass
            await restore_system_proxy()
            await restore_system_dns()
            await asyncio.sleep(15)

if __name__ == "__main__":
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try: loop.run_until_complete(main())
        finally:
            pending = asyncio.all_tasks(loop=loop)
            for task in pending: task.cancel()
            if pending: loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()
    except KeyboardInterrupt: log("Exiting...", "INFO")
    finally:
        cleanup_child_processes()
        sys.exit(0)