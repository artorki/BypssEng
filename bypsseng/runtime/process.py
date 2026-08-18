import asyncio
import subprocess
import aiohttp
import os
import platform
import logging
from core.logger import log

logger = logging.getLogger("NetAnalyzer")

class ProcessManager:
    def __init__(self):
        self.active_proc = None
        self.aux_procs = {}
        self.strategy_lock = asyncio.Lock()
        self.job_handle = None
        
        if platform.system().lower() == 'windows':
            try:
                import win32job
                import win32api
                self.job_handle = win32job.CreateJobObject(None, "BypssEngJob")
                info = win32job.QueryInformationJobObject(self.job_handle, win32job.JobObjectExtendedLimitInformation)
                info['BasicLimitInformation']['LimitFlags'] = win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                win32job.SetInformationJobObject(self.job_handle, win32job.JobObjectExtendedLimitInformation, info)
                log("Job Object created for zombie process prevention.", "PASS")
            except ImportError:
                log("pywin32 not installed. Zombie prevention disabled.", "WARN")
            except Exception as e:
                logger.error(f"Job Object creation failed: {e}")

    def _assign_to_job(self, proc):
        if self.job_handle:
            try:
                import win32job, win32api
                win32job.AssignProcessToJobObject(self.job_handle, win32api.OpenProcess(win32job.PROCESS_ALL_ACCESS, False, proc.pid))
            except Exception as e:
                logger.debug(f"Failed to assign process to job: {e}")

    def kill_stale_processes(self):
        log("Skipping global stale proxy processes cleanup...", "SOL")

    def cleanup_child_processes(self):
        if self.aux_procs:
            for p in self.aux_procs.values():
                if p and p.returncode is None:
                    try: p.terminate()
                    except: pass
            self.aux_procs.clear()

        if self.active_proc and self.active_proc.returncode is None:
            try:
                self.active_proc.terminate()
                try: self.active_proc.wait(timeout=0.5)
                except subprocess.TimeoutExpired: self.active_proc.kill()
            except Exception as e: log(f"Error during process cleanup: {e}", "WARN")
            finally: self.active_proc = None

    async def suspend_process(self, proc):
        try:
            import psutil
            p = psutil.Process(proc.pid)
            p.suspend()
            log(f"Process {proc.pid} suspended to save resources.", "INFO")
        except Exception as e:
            logger.debug(f"Suspend failed: {e}")

    async def resume_process(self, proc):
        try:
            import psutil
            p = psutil.Process(proc.pid)
            p.resume()
            log(f"Process {proc.pid} resumed.", "INFO")
        except Exception as e:
            logger.debug(f"Resume failed: {e}")

    async def test_current_proxy_health(self, proxy_port):
        if not self.active_proc or self.active_proc.returncode is not None: return False
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.get("https://cp.cloudflare.com/generate_204", proxy=proxy_url) as r:
                    return r.status in [204, 200]
        except Exception: return False

pm = ProcessManager()
