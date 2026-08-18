import asyncio
import subprocess
import aiohttp
from core.logger import log

class ProcessManager:
    def __init__(self):
        self.active_proc = None
        self.aux_proc = None
        self.strategy_lock = asyncio.Lock()

    def kill_stale_processes(self):
        log("Skipping global stale proxy processes cleanup...", "SOL")

    def cleanup_child_processes(self):
        if self.aux_proc and self.aux_proc.returncode is None:
            try:
                self.aux_proc.terminate()
                try: self.aux_proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired: self.aux_proc.kill()
            except Exception: pass
            finally: self.aux_proc = None

        if self.active_proc and self.active_proc.returncode is None:
            try:
                self.active_proc.terminate()
                try: self.active_proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired: self.active_proc.kill()
            except Exception as e: log(f"Error during process cleanup: {e}", "WARN")
            finally: self.active_proc = None

    async def test_current_proxy_health(self, proxy_port):
        if not self.active_proc or self.active_proc.returncode is not None: return False
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.get("https://cp.cloudflare.com/generate_204", proxy=proxy_url) as r:
                    return r.status in [204, 200]
        except Exception: return False

pm = ProcessManager()
