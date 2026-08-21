


import asyncio
import aiohttp.web
import sys
import os
import time
import webbrowser
import argparse


PACKAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bypsseng")
if PACKAGE_DIR not in sys.path:
    sys.path.insert(0, PACKAGE_DIR)

import BypssEng
import api_server
from engine.orchestrator import Orchestrator
from infrastructure.system_network import SystemNetworkManager
from infrastructure.runtime_session import RuntimeSession
from telemetry.storage import TelemetryDB
from telemetry.statistics import AdaptiveStatistics
from runtime.admin_service import AdminIPCServer
from core.logger import log as original_log
import telemetry.storage as telemetry_module

async def main():

    net_manager = SystemNetworkManager(BypssEng.STATE_FILE)
    

    BypssEng.log("Performing startup recovery policy...", "SOL")
    await net_manager.restore_system_state()
    

    runtime_session = RuntimeSession()
    runtime_session.setup_dynamic_ports()
    

    db = TelemetryDB(BypssEng.DB_PATH)
    await db.init()
    await db.cleanup_old_logs()
    adaptive_stats = AdaptiveStatistics(db)
    

    admin_server = None
    admin_port = 8765
    if BypssEng.is_root_or_admin():
        try:
            admin_server = AdminIPCServer(port=admin_port, network_manager=net_manager)
            auth_token = await admin_server.start()
            BypssEng.log(f"Admin IPC Service started securely on port {admin_port}", "PASS")
        except Exception as e:
            BypssEng.log(f"Failed to start Admin IPC Service: {e}", "WARN")
    else:
        BypssEng.log("Admin rights missing. Network changes will run in user-space.", "WARN")


    import core.logger
    original_log_func = core.logger.log
    def hooked_log(msg, type="INFO", color_override=None):
        original_log_func(msg, type, color_override)
        log_data = {"ts": time.time(), "level": type, "msg": msg}
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(api_server.broadcaster.broadcast("log", log_data))
            loop.create_task(db.insert_log(type, msg))
        except RuntimeError: pass
        

    BypssEng.log = hooked_log
    core.logger.log = hooked_log
    import engine.orchestrator; engine.orchestrator.log = hooked_log
    import diagnosis.health; diagnosis.health.log = hooked_log
    import diagnosis.connectivity; diagnosis.connectivity.log = hooked_log
    import diagnosis.dns; diagnosis.dns.log = hooked_log
    import diagnosis.tls; diagnosis.tls.log = hooked_log
    import diagnosis.bandwidth; diagnosis.bandwidth.log = hooked_log
    import diagnosis.transport; diagnosis.transport.log = hooked_log
    import runtime.process; runtime.process.log = hooked_log
    import runtime.ports; runtime.ports.log = hooked_log

    original_report = BypssEng.generate_network_report
    def hooked_report(states, applied_bypass="none", diagnosis=None, selected_method=None):
        verdict = original_report(states, applied_bypass, diagnosis, selected_method)
        report = {"states": states, "applied_bypass": applied_bypass, "diagnosis": diagnosis, "selected_method": selected_method, "verdict": verdict}
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(telemetry_module.db.insert_network_event(report))
            loop.create_task(api_server.broadcaster.broadcast("network_update", report))
        except RuntimeError: pass
    BypssEng.generate_network_report = hooked_report


    app = await api_server.create_app()
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, '127.0.0.1', 8080)
    await site.start()
    
    BypssEng.log(f"Dashboard is running on http://127.0.0.1:8080", "SOL")
    webbrowser.open(f"http://127.0.0.1:8080?token={api_server.DASHBOARD_TOKEN}")


    async def executor_wrapper(states, diagnosis_result):
        return await BypssEng.bypass_executor_wrapper(states, diagnosis_result, runtime_session, net_manager, db, adaptive_stats)

    orchestrator = Orchestrator(
        app_dir=BypssEng.APP_DIR,
        bypass_executor=executor_wrapper,  # Fixed: Passed correctly to constructor
        telemetry_db=db,
        runtime_session=runtime_session,
        net_manager=net_manager,
        report_callback=BypssEng.generate_network_report
    )
    orchestrator.local_http_port = runtime_session.local_http_port


    engine_task = asyncio.create_task(orchestrator.run())
    
    try:
        await engine_task
    except asyncio.CancelledError:
        pass
    finally:
        if admin_server: await admin_server.stop()
        await runner.cleanup()
        await db.close()
        runtime_session.release_reserved_ports()
        BypssEng.pm.cleanup_child_processes()

async def safe_cleanup():
    try:
        net_manager = SystemNetworkManager(BypssEng.STATE_FILE)
        state = net_manager.load_state()
        if state.get('proxy_backed_up') or state.get('dns_changed'):
            await net_manager.restore_system_state()
    except Exception as e:
        print(f"Error during safe cleanup: {e}")

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
            pending = asyncio.all_tasks(loop=loop)
            for task in pending: task.cancel()
            if pending: loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception: pass
        loop.close()
        print("Shutdown complete.")