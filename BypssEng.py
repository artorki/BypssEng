# BypssEng.py - Absolute Final Version (Post-Phase 11)
# Incorporates all architectural changes from HANDOFF Sec 4, 11, 18, 19, 24, 54, 87
# Fixed: Pipe Deadlock Prevention and Async Process Cleanup

import asyncio
import logging
import argparse
import os
import sys
import time
import json
import platform
import inspect

# Section 38: Standard Packaging fallback
PACKAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bypsseng")
if PACKAGE_DIR not in sys.path:
    sys.path.insert(0, PACKAGE_DIR)

from core.logger import log, Colors
from config.models import CONFIG
from engine.orchestrator import Orchestrator
from bypsseng.domain.models import DecisionExplanation
from infrastructure.system_network import SystemNetworkManager
from infrastructure.runtime_session import RuntimeSession
from runtime.process import pm
from strategies.registry import get_strategy
from decision.scorer import score_strategy
from telemetry.storage import TelemetryDB
from telemetry.statistics import AdaptiveStatistics
from core.utils import parse_config_link, find_binary, atomic_write_json
from diagnosis.health import scan_clean_cdn_ips
import aiohttp

# Paths Configuration
APP_DIR = PACKAGE_DIR
BIN_DIR = os.path.join(APP_DIR, "bin")
DATA_DIR = os.path.join(APP_DIR, "Data")
os.makedirs(DATA_DIR, exist_ok=True)

STATE_FILE = os.path.join(DATA_DIR, "state.json")
UNIFIED_CONFIG_FILE = os.path.join(DATA_DIR, "cnfg.json")
REPORT_FILE = os.path.join(DATA_DIR, "network_report.json")
DB_PATH = os.path.join(DATA_DIR, "telemetry.db")
CORE_DIR = os.path.join(APP_DIR, "core")

logger = logging.getLogger("NetAnalyzer")
DIAGNOSE_ONLY = False

# ------------------------------------------------------------------
# Core Binaries Discovery
# ------------------------------------------------------------------
BINARY_PATHS = {
    "xray": find_binary("xray", BIN_DIR), 
    "hysteria": find_binary("hysteria", BIN_DIR),
    "tor": find_binary("tor", BIN_DIR), 
    "snowflake": find_binary("snowflake-client", BIN_DIR),
    "lyrebird": find_binary("lyrebird", BIN_DIR), 
    "tuic": find_binary("tuic", BIN_DIR),
    "naive": find_binary("naive", BIN_DIR), 
    "psiphon": find_binary("psiphon-tunnel-core", BIN_DIR),
    "dnstt-client": find_binary("dnstt-client", BIN_DIR),
}

# ------------------------------------------------------------------
# Helper Functions for API Server (Bridges to new Architecture)
# ------------------------------------------------------------------
def load_unified_config():
    if not os.path.exists(UNIFIED_CONFIG_FILE):
        return {"configs": [], "subscription_urls": [], "warp": None, "cloudflare_worker": None}
    try:
        with open(UNIFIED_CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"configs": [], "subscription_urls": [], "warp": None, "cloudflare_worker": None}

def generate_network_report(states, applied_bypass="none", diagnosis=None, selected_method=None):
    """Section 54: Machine-readable report generation with stable schema."""
    if not diagnosis:
        diagnosis = []
    if not selected_method:
        selected_method = "unknown"
    
    confidence = "low"
    severity_score = 30
    if selected_method == "healthy":
        confidence = "high"
        severity_score = 100
    elif selected_method == "starting":
        confidence = "low"
        severity_score = 0
    elif selected_method == "failed":
        confidence = "low"
        severity_score = 10
    
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "network_states": states, 
        "applied_bypass": applied_bypass, 
        "verdict": {
            "diagnosis": diagnosis, 
            "selected_method": selected_method, 
            "confidence": confidence, 
            "severity_score": severity_score
        }
    }
    try:
        atomic_write_json(REPORT_FILE, report)
    except Exception as e:
        logger.error(f"Report write failed: {e}")
    return report.get("verdict")

def is_root_or_admin():
    """Checks if the script is running with Administrator/root privileges."""
    if platform.system().lower() == 'windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    return hasattr(os, 'geteuid') and os.geteuid() == 0

def load_state():
    """Helper function for API Server to read network state."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

async def fetch_fresh_configs(wait=True):
    """Helper function for API Server to trigger config fetching."""
    try:
        sys.path.insert(0, CORE_DIR)
        import cnfg
        if inspect.iscoroutinefunction(cnfg.main):
            if wait:
                await cnfg.main()
            else:
                asyncio.create_task(cnfg.main())
        return True
    except ImportError:
        import subprocess
        cmd = [sys.executable, os.path.join(CORE_DIR, "cnfg.py")]
        proc = await asyncio.create_subprocess_exec(
            *cmd, 
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.PIPE, 
            cwd=DATA_DIR
        )
        if wait:
            await proc.communicate()
        return True

async def check_config_latency(parsed_creds):
    """Helper function for API Server to test config latency."""
    try:
        host = parsed_creds.get(f"{parsed_creds['protocol']}_server_ip")
        port = parsed_creds.get(f"{parsed_creds['protocol']}_port")
        if not host or not port:
            return None
        
        start = time.time()
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
        latency = round((time.time() - start) * 1000, 2)
        writer.close()
        await writer.wait_closed()
        return latency
    except Exception:
        return None

# ------------------------------------------------------------------
# Phase 2: Adaptive Bypass Executor (Integrated with Runtime & DI)
# ------------------------------------------------------------------
async def execute_bypass_and_connect(creds, dpi_state, runtime_session: RuntimeSession, net_manager: SystemNetworkManager):
    async with pm.strategy_lock:
        old_procs = pm.active_procs[:] if pm.active_procs else []
        old_socks = runtime_session.local_socks_port
        old_http = runtime_session.local_http_port

        runtime_session.setup_dynamic_ports()
        
        async def restore_state_on_failure():
            # Bug Fix: Added await for async cleanup
            await pm.cleanup_child_processes()
            runtime_session.local_socks_port = old_socks
            runtime_session.local_http_port = old_http
            if not DIAGNOSE_ONLY:
                await net_manager.set_system_proxy(False)

        strategy = get_strategy(
            creds, 
            None, 
            dpi_state, 
            runtime_session.local_socks_port, 
            runtime_session.local_http_port, 
            DATA_DIR, 
            BINARY_PATHS
        )
        if not strategy:
            await restore_state_on_failure()
            return False

        config_file, binary_name = await strategy.prepare()
        if not config_file:
            await restore_state_on_failure()
            return False

        try:
            strategy._config_file = config_file
            commands = strategy.processes()
            pm.active_procs = []
            
            # Bug Fix: Pipe Deadlock Prevention
            async def tail_logs(stream, prefix):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded_line = line.decode(errors='ignore').strip()
                    if any(k in decoded_line.lower() for k in ["error", "warn", "failed"]):
                        log(f"[{binary_name}] {decoded_line}", "INFO")

            for cmd in commands:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, 
                    stdout=asyncio.subprocess.PIPE, 
                    stderr=asyncio.subprocess.PIPE, 
                    cwd=DATA_DIR
                )
                pm._assign_to_job(proc)
                pm.active_procs.append(proc)
                
                # Start background tasks to drain pipes continuously
                if proc.stdout:
                    asyncio.create_task(tail_logs(proc.stdout, "STDOUT"))
                if proc.stderr:
                    asyncio.create_task(tail_logs(proc.stderr, "STDERR"))
            
            # Section 87: Give heavy strategies enough time to bootstrap
            wait_time = 3
            if creds["protocol"] in ["tor_proxy", "tor_snowflake", "psiphon"]:
                wait_time = 20  # Tor and Psiphon need more time to connect
            elif creds["protocol"] == "dnstt":
                wait_time = 10
                
            await asyncio.sleep(wait_time)
            proxy = f"http://127.0.0.1:{runtime_session.local_http_port}"
            
            success = False
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
                for url in ["https://cp.cloudflare.com/generate_204", "https://www.youtube.com/generate_204"]:
                    try:
                        async with session.get(url, proxy=proxy, allow_redirects=False) as resp:
                            if resp.status in [204, 200]:
                                log(f"Successfully connected via {creds['protocol'].upper()}!", "PASS")
                                if not DIAGNOSE_ONLY:
                                    if not await net_manager.set_system_proxy(True, runtime_session.local_http_port):
                                        await restore_state_on_failure()
                                        return False
                                for p in old_procs:
                                    if p.returncode is None:
                                        p.terminate()
                                success = True
                                break
                    except Exception:
                        continue
                    
                if not success:
                    log(f"Proxy failed to connect or bypass filtering.", "FAIL")
                    await restore_state_on_failure()
                    return False
                return True
        except Exception as e:
            log(f"Failed to start {binary_name}: {e}", "ERROR")
            await restore_state_on_failure()
            return False

async def bypass_executor_wrapper(states, diagnosis_result, runtime_session, net_manager, db, adaptive_stats):
    """Section 24: Adaptive Engine Integration. Wires statistics into the scoring loop."""
    log(f"Executing bypass based on diagnosis: {diagnosis_result.condition}", "SOL")
    
    unified_cfg = load_unified_config()
    config_links = unified_cfg.get("configs", [])
    parsed_configs = [parse_config_link(link) for link in config_links]
    valid_configs = [c for c in parsed_configs if c["protocol"] != "unsupported"]
    
    # اضافه شدن Fallbackهای داخلی با اولویت WARP (با IP تمیز)
    if unified_cfg.get("warp"): 
        # اسکن IP تمیز برای WARP
        clean_ips = await scan_clean_cdn_ips(cdn_provider="cloudflare", worker_host="engage.cloudflareclient.com", worker_path="/", count=3)
        if clean_ips:
            log(f"Found {len(clean_ips)} clean Cloudflare IPs for WARP. Adding WARP as primary fallback.", "SOL")
            valid_configs.insert(0, {"protocol": "warp", "warp_data": unified_cfg["warp"], "custom_endpoint": f"{clean_ips[0]}:2408"})
        else:
            valid_configs.append({"protocol": "warp", "warp_data": unified_cfg["warp"]})
            
    if unified_cfg.get("cloudflare_worker"): 
        valid_configs.append({"protocol": "cloudflare_worker", "worker_data": unified_cfg["cloudflare_worker"]})
    if BINARY_PATHS.get("psiphon"): 
        valid_configs.append({"protocol": "psiphon"})
    if BINARY_PATHS.get("dnstt-client") and unified_cfg.get("dnstt"): 
        valid_configs.append({"protocol": "dnstt", "dnstt_domain": unified_cfg["dnstt"].get("domain"), "dnstt_pubkey": unified_cfg["dnstt"].get("pubkey")})
        
    valid_configs.extend([{"protocol": "tor_proxy"}, {"protocol": "tor_snowflake"}])

    scored_candidates = []
    for c in valid_configs:
        score = await score_strategy(c["protocol"], states, db, adaptive_stats)
        scored_candidates.append((c, score))
    scored_candidates.sort(key=lambda x: x[1].score, reverse=True)
    
    alternatives = {}
    selected_strategy = None
    explanation_evidence = []
    
    for creds, score in scored_candidates:
        if score.score > 0.1 or creds["protocol"] in ["tor_proxy", "tor_snowflake", "psiphon", "dnstt", "warp"]:
            log(f"Attempting strategy: {creds['protocol']} (Score: {score.score:.2f})", "INFO")
            success = await execute_bypass_and_connect(creds, states.get('dpi'), runtime_session, net_manager)
            if success:
                selected_strategy = creds["protocol"]
                explanation_evidence = score.reasons
                await db.record_strategy_outcome(creds["protocol"], diagnosis_result.condition, True)
                break
            else:
                alternatives[creds["protocol"]] = score.score
                await db.record_strategy_outcome(creds["protocol"], diagnosis_result.condition, False)
                
    if selected_strategy:
        generate_network_report(states, f"connected_via_{selected_strategy}", [diagnosis_result.condition], selected_strategy)
        return True, DecisionExplanation(selected=selected_strategy, alternatives=alternatives, evidence=explanation_evidence)
    
    generate_network_report(states, "failed", [diagnosis_result.condition], "failed")
    return False, None

# ------------------------------------------------------------------
# Phase 6 & 10: Main Entry Point with Crash Recovery & Watchdog
# ------------------------------------------------------------------
async def main():
    """Composition Root: Wires all dependencies and runs the Orchestrator (Section 4, 87)."""
    
    # 1. Setup Infrastructure (Phase 19: SystemNetworkManager)
    net_manager = SystemNetworkManager(STATE_FILE)
    
    # 2. Crash Recovery (Phase 87: deterministic lifecycle)
    log("Performing startup recovery policy...", "SOL")
    await net_manager.restore_system_state()
    
    # 3. Setup Runtime Session (Phase 18: Encapsulated State)
    runtime_session = RuntimeSession()
    runtime_session.setup_dynamic_ports()
    
    # 4. Setup Telemetry & Adaptive Learning (Phase 11 DI, Phase 24/25 Learning)
    db = TelemetryDB(DB_PATH)
    await db.init()
    await db.cleanup_old_logs()
    adaptive_stats = AdaptiveStatistics(db)
    
    # 5. Setup Orchestrator with all injected dependencies
    async def executor_wrapper(states, diagnosis_result):
        return await bypass_executor_wrapper(states, diagnosis_result, runtime_session, net_manager, db, adaptive_stats)

    orchestrator = Orchestrator(
        app_dir=APP_DIR,
        bypass_executor=executor_wrapper,
        telemetry_db=db,
        runtime_session=runtime_session,
        net_manager=net_manager,
        report_callback=generate_network_report,
        fetch_config_callback=fetch_fresh_configs  # Added for auto-fetching configs
    )
    orchestrator.local_http_port = runtime_session.local_http_port

    # Section 88: Final product vision - Adaptive Engine
    print(f"{Colors.BOLD}Advanced Adaptive Anti-Censorship Engine Started.{Colors.ENDC}\n")
    
    # Section 73: Productionization - Watchdog loop
    while True:
        try:
            await orchestrator.run()
            break  # Exit if run finishes normally
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log(f"CRITICAL: Engine crashed unexpectedly: {e}. Restarting in 5 seconds...", "ERROR")
            logger.exception("Watchdog caught exception")
            await asyncio.sleep(5)
            # Reset state machine for fresh start
            from engine.state_machine import EngineState
            orchestrator.sm.state = EngineState.RESELECTING

    # Cleanup on exit
    await db.close()
    runtime_session.release_reserved_ports()
    await pm.cleanup_child_processes()
    if not DIAGNOSE_ONLY:
        await net_manager.set_system_proxy(False)

if __name__ == "__main__":
    # Section 54: CLI Modes (Diagnose-only, Research)
    parser = argparse.ArgumentParser()
    parser.add_argument("--diagnose-only", action="store_true", help="Only run tests, output machine-readable report.json")
    parser.add_argument("--research", action="store_true", help="Enable extensive logging and telemetry")
    args = parser.parse_args()
    if args.diagnose_only:
        DIAGNOSE_ONLY = True

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        log("Shutting down gracefully...", "INFO")
    finally:
        pending = asyncio.all_tasks(loop=loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.close()
        log("Shutdown complete.", "INFO")
