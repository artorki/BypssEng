import asyncio
import subprocess
from core.logger import log

class ProcessManager:
    def __init__(self):
        self.active_proc = None
        self.dnstt_proc = None
        self.xray_lock = asyncio.Lock()

    def kill_stale_processes(self):
        log("Skipping global stale proxy processes cleanup...", "SOL")

    def cleanup_child_processes(self):
        if self.dnstt_proc and self.dnstt_proc.returncode is None:
            try:
                self.dnstt_proc.terminate()
                try: self.dnstt_proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired: self.dnstt_proc.kill()
            except Exception: pass
            finally: self.dnstt_proc = None

        if self.active_proc and self.active_proc.returncode is None:
            try:
                self.active_proc.terminate()
                try: self.active_proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired: self.active_proc.kill()
            except Exception as e: log(f"Error during process cleanup: {e}", "WARN")
            finally: self.active_proc = None

pm = ProcessManager()
