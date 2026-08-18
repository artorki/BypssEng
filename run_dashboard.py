import asyncio
import aiohttp.web
import sys
import os
import time
import atexit
import webbrowser
import argparse

PACKAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bypsseng")
if PACKAGE_DIR not in sys.path:
    sys.path.insert(0, PACKAGE_DIR)

import BypssEng
import telemetry.storage as telemetry
import api_server
from engine.orchestrator import Orchestrator

async def main():
    await telemetry.init_db()
    await telemetry.cleanup_old_logs()

    try: atexit.unregister(BypssEng.cleanup_child_processes)
    except Exception: pass

    async def noop_prompt(): pass
    BypssEng.prompt_and_fetch_custom_configs = noop_prompt

    original_log = BypssEng.log
    def hooked_log(msg, type="INFO", color_override=None):
        original_log(msg, type, color_override)
        log_data = {"ts": time.time(), "level": type, "msg": msg}
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(api_server.broadcaster.broadcast("log", log_data))
            loop.create_task(telemetry.insert_log(type, msg))
        except RuntimeError: pass
        
    BypssEng.log = hooked_log
    import core.logger
    core.logger.log = hooked_log
    import engine.orchestrator
    engine.orchestrator.log = hooked_log
    import diagnosis.health
    diagnosis.health.log = hooked_log
    import diagnosis.connectivity
    diagnosis.connectivity.log = hooked_log
    import diagnosis.dns
    diagnosis.dns.log = hooked_log
    import diagnosis.tls
    diagnosis.tls.log = hooked_log
    import diagnosis.bandwidth
    diagnosis.bandwidth.log = hooked_log
    import diagnosis.transport
    diagnosis.transport.log = hooked_log
    import runtime.process
    runtime.process.log = hooked_log
    import runtime.ports
    runtime.ports.log = hooked_log

    original_report = BypssEng.generate_network_report
    def hooked_report(states, applied_bypass="none", diagnosis=None, selected_method=None):
        verdict = original_report(states, applied_bypass, diagnosis, selected_method)
        report = {"states": states, "applied_bypass": applied_bypass, "diagnosis": diagnosis, "selected_method": selected_method, "verdict": verdict}
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(telemetry.insert_network_event(report))
            loop.create_task(api_server.broadcaster.broadcast("network_update", report))
            if verdict:
                loop.create_task(telemetry.insert_decision_telemetry(
                    diagnosis=verdict.get("diagnosis", []),
                    confidence=verdict.get("confidence", "unknown"),
                    selected_strategy=verdict.get("selected_method", "unknown"),
                    score=verdict.get("severity_score", 0),
                    result=applied_bypass,
                    explanation=verdict.get("explanation")
                ))
        except RuntimeError: pass
    BypssEng.generate_network_report = hooked_report

    app = await api_server.create_app()
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, '127.0.0.1', 8080)
    await site.start()
    
    BypssEng.log(f"Dashboard is running on http://127.0.0.1:8080", "SOL")
    webbrowser.open(f"http://127.0.0.1:8080?token={api_server.DASHBOARD_TOKEN}")

    orchestrator = Orchestrator(BypssEng.APP_DIR, BypssEng.bypass_executor_wrapper, BypssEng.LOCAL_HTTP_PORT)
    engine_task = asyncio.create_task(orchestrator.run())
    
    try: await engine_task
    except asyncio.CancelledError: pass
    finally:
        await runner.cleanup()
        await telemetry.close_db()

async def safe_cleanup():
    try:
        state = BypssEng.load_state()
        if state.get('proxy_backed_up'): await BypssEng.restore_system_proxy()
        if state.get('dns_changed'): await BypssEng.restore_system_dns()
    except Exception as e: print(f"Error during safe cleanup: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BypssEng Advanced Anti-Censorship Engine")
    parser.add_argument("--diagnose-only", action="store_true", help="Only run tests, do not change system proxy/DNS")
    args = parser.parse_args()
    if args.diagnose_only: BypssEng.DIAGNOSE_ONLY = True

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    except (KeyboardInterrupt, SystemExit):
        print("\nShutting down gracefully, restoring network state...")
        loop.run_until_complete(safe_cleanup())
    finally:
        try:
            BypssEng.cleanup_child_processes()
        except Exception: pass
        try:
            pending = asyncio.all_tasks(loop=loop)
            for task in pending: task.cancel()
            if pending: loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception: pass
        loop.close()
        print("Shutdown complete.")
