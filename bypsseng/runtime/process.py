import asyncio
import subprocess
from core.logger import log

class ProcessManager:
    def __init__(self):
        self.xray_proc = None
        self.dnstt_proc = None
        self.xray_lock = asyncio.Lock()

    def kill_stale_processes(self):
        log("Skipping global stale proxy processes cleanup to prevent killing other instances.", "SOL")

    def cleanup_child_processes(self):
        if self.dnstt_proc and self.dnstt_proc.returncode is None:
            try:
                self.dnstt_proc.terminate()
                try: self.dnstt_proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired: self.dnstt_proc.kill()
            except Exception: pass
            finally: self.dnstt_proc = None

        if self.xray_proc and self.xray_proc.returncode is None:
            try:
                self.xray_proc.terminate()
                try: self.xray_proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired: self.xray_proc.kill()
            except Exception as e: log(f"Error during process cleanup: {e}", "WARN")
            finally: self.xray_proc = None

pm = ProcessManager()
