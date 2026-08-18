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
import hashlib
import inspect
import re
import ipaddress

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PACKAGE_DIR = os.path.join(SCRIPT_DIR, "bypsseng")
if PACKAGE_DIR not in sys.path:
    sys.path.insert(0, PACKAGE_DIR)

from config.models import CONFIG
from engine.models import DiagnosisResult, DecisionExplanation
from engine.state_machine import EngineState, StateMachine
from engine.orchestrator import Orchestrator
from engine.supply_chain import SupplyChainManager
from core.logger import log, Colors
from core.network import get_resolver
from core.utils import parse_config_link, find_binary, get_proto_prefix, atomic_write_json
from runtime.process import pm
from runtime.ports import setup_dynamic_ports, release_reserved_ports
from strategies.registry import get_strategy
from decision.scorer import score_strategy
import telemetry.storage as telemetry

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
SUB_CACHE_FILE = os.path.join(DATA_DIR, "my_configs.config")
WORKING_CONFIGS_CACHE = os.path.join(DATA_DIR, "working_configs.cache")
REPORT_FILE = os.path.join(DATA_DIR, "network_report.json")
STATE_FILE = os.path.join(DATA_DIR, "state.json")
LOCK_FILE = os.path.join(DATA_DIR, "engine.lock")
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
        except Exception as e: logger.error(f"State load error: {e}"); return {}
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
    except Exception as e: logger.error(f"State load error in cleanup: {e}")
    release_reserved_ports(); release_lock()

atexit.register(cleanup_child_processes)

async def check_config_latency(creds):
    async with latency_sem:
        proto = creds["protocol"]; prefix = get_proto_prefix(proto)
        host = creds.get(f"{prefix}_server_ip"); port = creds.get(f"{prefix}_port")
        if not host or not port: return None
        try:
            start = time.time(); reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
            latency = round((time.time() - start) * 1000, 2); writer.close(); await writer.wait_closed(); return latency
        except Exception as e: logger.debug(f"Latency check error: {e}"); return None

async def test_proxy_throughput(proxy_url, timeout=15):
    import aiohttp
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
        except Exception as e: logger.debug(f"Proxy throughput error: {e}"); continue
    return 0

async def execute_bypass_and_connect(creds, all_configs=None, dpi_state='none'):
    global LOCAL_SOCKS_PORT, LOCAL_HTTP_PORT
    async with pm.xray_lock:
        old_xray_proc = pm.xray_proc if (pm.xray_proc and pm.xray_proc.returncode is None) else None
        old_proxy_active = old_xray_proc is not None
        old_socks_port = LOCAL_SOCKS_PORT; old_http_port = LOCAL_HTTP_PORT

        LOCAL_SOCKS_PORT, LOCAL_HTTP_PORT = setup_dynamic_ports()
        log_tasks = []

        async def restore_state_on_failure():
            for t in log_tasks:
                try: t.cancel()
                except Exception: pass
            if pm.xray_proc and pm.xray_proc.returncode is None and pm.xray_proc is not old_xray_proc:
                try: pm.xray_proc.terminate(); await asyncio.wait_for(pm.xray_proc.wait(), timeout=3)
                except Exception:
                    try: pm.xray_proc.kill()
                    except Exception as e: logger.error(f"Kill new xray error: {e}")
            release_reserved_ports()
            if old_proxy_active:
                pm.xray_proc = old_xray_proc; LOCAL_SOCKS_PORT = old_socks_port; LOCAL_HTTP_PORT = old_http_port
            else:
                pm.xray_proc = None; await restore_system_proxy()

        latency = await check_config_latency(creds)
        if latency is None and creds["protocol"] not in ("cloudflare_worker", "tor_snowflake", "warp", "tor_proxy", "psiphon", "dnstt", "hysteria2", "tuic"):
            proto_prefix = get_proto_prefix(creds['protocol']); server_ip = creds.get(f"{proto_prefix}_server_ip")
            log(f"  -> Server {server_ip} is unreachable. Skipping...", "WARN"); await restore_state_on_failure(); return False

        strategy = get_strategy(creds, all_configs, dpi_state, LOCAL_SOCKS_PORT, LOCAL_HTTP_PORT, DATA_DIR, BINARY_PATHS)
        if not strategy: log(f"Strategy for {creds['protocol']} not found.", "FAIL"); await restore_state_on_failure(); return False

        config_file, binary_name = await strategy.prepare()
        if not config_file: await restore_state_on_failure(); return False

        binary_path = strategy.get_binary_path()
        if not binary_path or not os.path.isfile(binary_path): log(f"{binary_name} is not installed.", "FAIL"); await restore_state_on_failure(); return False

        abs_config_file = os.path.join(DATA_DIR, config_file)
        cmd_args = strategy.get_command_args(binary_path, abs_config_file)

        try:
            release_reserved_ports()
            pm.xray_proc = await asyncio.create_subprocess_exec(*cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc = pm.xray_proc
            
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
            
            import aiohttp
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
                success = False
                for url in ["https://cp.cloudflare.com/generate_204", "https://www.google.com/generate_204"]:
                    if proc.returncode is not None: break
                    try:
                        async with session.get(url, proxy=proxy) as resp:
                            if resp.status in [204, 200, 301, 302]:
                                log(f"Successfully connected via {creds['protocol'].upper()}!", "PASS")
                                if not await set_system_proxy(True, LOCAL_HTTP_PORT): await restore_state_on_failure(); return False
                                if old_xray_proc and old_xray_proc.returncode is None: old_xray_proc.terminate()
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
    
    unified_cfg = load_unified_config()
    config_links = load_working_configs() if os.path.exists(WORKING_CONFIGS_CACHE) else unified_cfg.get("configs", [])
    
    parsed_configs = [parse_config_link(link) for link in config_links]
    valid_configs = [c for c in parsed_configs if c["protocol"] != "unsupported"]
    
    if unified_cfg.get("warp"): valid_configs.append({"protocol": "warp", "warp_data": unified_cfg["warp"]})
    if unified_cfg.get("cloudflare_worker"): valid_configs.append({"protocol": "cloudflare_worker", "worker_data": unified_cfg["cloudflare_worker"]})
    if unified_cfg.get("psiphon") is not None: valid_configs.append({"protocol": "psiphon"})
    valid_configs.extend([{"protocol": "tor_proxy"}, {"protocol": "tor_snowflake"}])

    scored_candidates = []
    for c in valid_configs:
        score = await score_strategy(c["protocol"], states)
        scored_candidates.append((c, score))
    
    scored_candidates.sort(key=lambda x: x[1].score, reverse=True)
    
    for creds, score in scored_candidates:
        if score.score > 0.1:
            log(f"Attempting strategy: {creds['protocol']} (Score: {score.score:.2f}, Reasons: {score.reasons})", "INFO")
            success = await execute_bypass_and_connect(creds, dpi_state=states.get('dpi'))
            if success:
                await telemetry.record_strategy_outcome(creds["protocol"], diagnosis_result.condition, True)
                return True
            else:
                await telemetry.record_strategy_outcome(creds["protocol"], diagnosis_result.condition, False)
    return False

async def test_current_proxy_health():
    if not pm.xray_proc or pm.xray_proc.returncode is not None: return False
    proxy_url = f"http://127.0.0.1:{LOCAL_HTTP_PORT}"
    try:
        import aiohttp
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
            async with s.get("https://cp.cloudflare.com/generate_204", proxy=proxy_url) as r: return r.status in [204, 200]
    except Exception: return False

async def main():
    import datetime
    current_year = datetime.datetime.now().year
    if current_year < 2025: log(f"CRITICAL: System time is set to {current_year}.", "ERROR")
    
    await telemetry.init_db()
    await telemetry.cleanup_old_logs()
    
    acquire_lock()
    pm.kill_stale_processes()
    
    log("Performing startup recovery policy...", "SOL")
    state = load_state()
    if state.get('proxy_backed_up') or state.get('proxy_enabled'):
        if not await restore_system_proxy(): sys.exit(1)
    if state.get('dns_backed_up') or state.get('dns_changed'):
        if not await restore_system_dns(): sys.exit(1)

    print(f"{Colors.BOLD}Advanced Analyzer & Auto-Bypass Engine Started (CLI Mode).{Colors.ENDC}\n")

    orchestrator = Orchestrator(APP_DIR, bypass_executor_wrapper)
    try:
        await orchestrator.run()
    finally:
        await telemetry.close_db()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="BypssEng Advanced Anti-Censorship Engine")
    parser.add_argument("--diagnose-only", action="store_true", help="Only run tests, do not change system proxy/DNS")
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
    finally: cleanup_child_processes(); sys.exit(0)
