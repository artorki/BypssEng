# BypssEng - artorki

import asyncio
import aiohttp.web
import sys
import os
import time
import atexit
import webbrowser

if getattr(sys, 'frozen', False):
    ROOT_DIR = os.path.dirname(sys.executable)
else:
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

CORE_DIR = os.path.join(ROOT_DIR, "Core")
sys.path.insert(0, CORE_DIR)
sys.path.insert(0, ROOT_DIR)

import BypssEng
import telemetry
import api_server

async def main():
    if getattr(sys, 'frozen', False):
        BypssEng.APP_DIR = ROOT_DIR
        BypssEng.CORE_DIR = CORE_DIR
        BypssEng.DATA_DIR = os.path.join(ROOT_DIR, "Data")
        os.makedirs(BypssEng.DATA_DIR, exist_ok=True)
        BypssEng.UNIFIED_CONFIG_FILE = os.path.join(BypssEng.DATA_DIR, "cnfg.json")
        BypssEng.SUB_CACHE_FILE = os.path.join(BypssEng.DATA_DIR, "my_configs.config")
        BypssEng.WORKING_CONFIGS_CACHE = os.path.join(BypssEng.DATA_DIR, "working_configs.cache")
        BypssEng.REPORT_FILE = os.path.join(BypssEng.DATA_DIR, "network_report.json")
        BypssEng.STATE_FILE = os.path.join(BypssEng.DATA_DIR, "state.json")
        BypssEng.LOCK_FILE = os.path.join(BypssEng.DATA_DIR, "engine.lock")

    await telemetry.init_db()

    try:
        atexit.unregister(BypssEng.cleanup_child_processes)
    except Exception:
        pass

    async def noop_prompt():
        pass
    BypssEng.prompt_and_fetch_custom_configs = noop_prompt

    original_log = BypssEng.log
    def hooked_log(msg, type="INFO", color_override=None):
        original_log(msg, type, color_override)
        log_data = {"ts": time.time(), "level": type, "msg": msg}
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(api_server.broadcaster.broadcast("log", log_data))
            loop.create_task(telemetry.insert_log(type, msg))
        except RuntimeError:
            pass

    BypssEng.log = hooked_log

    original_report = BypssEng.generate_network_report
    def hooked_report(states, applied_bypass="none", diagnosis=None, selected_method=None):
        original_report(states, applied_bypass, diagnosis, selected_method)
        report = {
            "states": states,
            "applied_bypass": applied_bypass,
            "diagnosis": diagnosis,
            "selected_method": selected_method
        }
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(telemetry.insert_network_event(report))
            loop.create_task(api_server.broadcaster.broadcast("network_update", report))
        except RuntimeError:
            pass

    BypssEng.generate_network_report = hooked_report

    app = await api_server.create_app()
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, '127.0.0.1', 8080)
    await site.start()
    
    BypssEng.log(f"Dashboard is running on http://127.0.0.1:8080", "SOL")
    
    webbrowser.open("http://127.0.0.1:8080")

    engine_task = asyncio.create_task(BypssEng.main())
    
    try:
        await engine_task
    except asyncio.CancelledError:
        pass
    finally:
        await runner.cleanup()
        await telemetry.close_db()

async def safe_cleanup():
    try:
        state = BypssEng.load_state()
        if state.get('proxy_backed_up'):
            await BypssEng.restore_system_proxy()
        if state.get('dns_changed'):
            await BypssEng.restore_system_dns()
    except Exception as e:
        print(f"Error during safe cleanup: {e}")

if __name__ == "__main__":
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
        except Exception:
            pass
        
        try:
            pending = asyncio.all_tasks(loop=loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()
        print("Shutdown complete.")

