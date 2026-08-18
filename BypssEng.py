# artorki

import os
import sys
import asyncio
import logging
import argparse
import platform

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
from core.utils import parse_config_link, find_binary, get_proto_prefix
from runtime.process import pm
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
CORE_DIR = os.path.join(APP_DIR, "core")
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

async def bypass_executor_wrapper(states, diagnosis_result):
    log(f"Executing bypass based on diagnosis: {diagnosis_result.condition}", "SOL")
    from decision.scorer import score_strategy
    candidates = ["vless_reality", "hysteria2", "tor_proxy"]
    
    for proto in candidates:
        score = await score_strategy(proto, states)
        log(f"Strategy {proto} scored: {score.score:.2f} (Reasons: {score.reasons})", "INFO")
        if score.score > 0.1:
            success = await execute_bypass_and_connect({"protocol": proto}, dpi_state=states.get('dpi'))
            if success:
                await telemetry.record_strategy_outcome(proto, diagnosis_result.condition, True)
                return True
            else:
                await telemetry.record_strategy_outcome(proto, diagnosis_result.condition, False)
    return False

async def main():
    import datetime
    current_year = datetime.datetime.now().year
    if current_year < 2025: log(f"CRITICAL: System time is set to {current_year}. This will cause SSL/TLS certificate errors!", "ERROR")
    
    await telemetry.init_db()
    await telemetry.cleanup_old_logs()
    
    # acquire_lock(); setup_signal_handlers(); pm.kill_stale_processes(); check_dependencies()
    
    log("Performing startup recovery policy...", "SOL")

    print(f"{Colors.BOLD}Advanced Analyzer & Auto-Bypass Engine Started (CLI Mode).{Colors.ENDC}\n")

    orchestrator = Orchestrator(APP_DIR, bypass_executor_wrapper)
    try:
        await orchestrator.run()
    finally:
        await telemetry.close_db()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BypssEng Advanced Anti-Censorship Engine")
    parser.add_argument("--diagnose-only", action="store_true", help="Only run tests, do not change system proxy/DNS")
    args = parser.parse_args()
    if args.diagnose_only: DIAGNOSE_ONLY = True

    try:
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        try: 
            loop.run_until_complete(main())
        finally:
            pending = asyncio.all_tasks(loop=loop)
            for task in pending: task.cancel()
            if pending: loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens()); loop.close()
    except KeyboardInterrupt: log("Exiting...", "INFO")
    finally: 
        # cleanup_child_processes()
        sys.exit(0)
