import asyncio
import subprocess
import aiohttp
import os
import platform
import logging
from typing import List, Optional

logger = logging.getLogger("NetAnalyzer")

class ProcessManager:
    def __init__(self):
        self.active_procs: List[asyncio.subprocess.Process] = []
        self.bootstrap_procs: List[asyncio.subprocess.Process] = []
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
                logger.info("Job Object created for zombie process prevention.")
            except ImportError:
                logger.warning("pywin32 not installed. Zombie prevention disabled.")
            except Exception as e:
                logger.error(f"Job Object creation failed: {e}")

    def _assign_to_job(self, proc: asyncio.subprocess.Process):
        if self.job_handle:
            try:
                import win32job, win32api
                win32job.AssignProcessToJobObject(self.job_handle, win32api.OpenProcess(win32job.PROCESS_ALL_ACCESS, False, proc.pid))
            except Exception as e:
                logger.debug(f"Failed to assign process to job: {e}")

    def register_bootstrap_proc(self, proc: Optional[asyncio.subprocess.Process]):

        if proc is None:
            return
        self.bootstrap_procs.append(proc)
        self._assign_to_job(proc)
        logger.info(f"Bootstrap process registered (PID: {proc.pid}).")

    async def stop_bootstrap_proc(self, proc: Optional[asyncio.subprocess.Process]):

        if proc is None:
            return
        if proc in self.bootstrap_procs:
            self.bootstrap_procs.remove(proc)
        if proc.returncode is None:
            try:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=10)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                logger.info(f"Bootstrap process stopped (PID: {proc.pid}).")
            except Exception as e:
                logger.error(f"Error stopping bootstrap process: {e}")

    async def cleanup_bootstrap_procs(self):

        for proc in self.bootstrap_procs[:]:
            await self.stop_bootstrap_proc(proc)

    def kill_stale_processes(self):
        try:
            import psutil
            target_names = ["xray", "xray.exe", "tor", "tor.exe", "hysteria", "tuic", "naive", "sing-box", "dnstt-client"]
            current_pids = [p.pid for p in self.active_procs + self.bootstrap_procs if p and p.returncode is None]
            
            killed_count = 0
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] and proc.info['name'].lower() in target_names:
                    if proc.info['pid'] not in current_pids:
                        logger.warning(f"Killing stale orphan process: {proc.info['name']} (PID: {proc.info['pid']})")
                        try: proc.kill()
                        except: pass
                        killed_count += 1
            if killed_count > 0:
                logger.info(f"Cleaned up {killed_count} stale proxy processes.")
        except ImportError:
            logger.warning("psutil not installed. Cannot kill stale processes.")
        except Exception as e:
            logger.error(f"Error killing stale processes: {e}")

    async def cleanup_child_processes(self):
        for proc in self.active_procs:
            if proc and proc.returncode is None:
                try:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=0.5)
                    except asyncio.TimeoutError:
                        proc.kill()
                except Exception as e:
                    logger.error(f"Error during process cleanup: {e}")
        self.active_procs.clear()

    async def test_current_proxy_health(self, proxy_port: int) -> bool:
        if not self.active_procs: return False
        for proc in self.active_procs:
            if proc.returncode is not None: return False
                
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.get("https://cp.cloudflare.com/generate_204", proxy=proxy_url) as r:
                    return r.status in [204, 200]
        except Exception:
            return False

    async def suspend_process(self, proc: asyncio.subprocess.Process):
        try:
            import psutil
            p = psutil.Process(proc.pid)
            p.suspend()
            logger.info(f"Process {proc.pid} suspended to save resources.")
        except Exception as e:
            logger.debug(f"Suspend failed: {e}")

    async def resume_process(self, proc: asyncio.subprocess.Process):
        try:
            import psutil
            p = psutil.Process(proc.pid)
            p.resume()
            logger.info(f"Process {proc.pid} resumed.")
        except Exception as e:
            logger.debug(f"Resume failed: {e}")

pm = ProcessManager()