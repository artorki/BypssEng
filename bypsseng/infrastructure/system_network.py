


import os
import json
import platform
import ctypes
import shutil
import re
import ipaddress
import logging
import asyncio
import subprocess
from typing import Optional, List, Dict

logger = logging.getLogger("NetAnalyzer")

class SystemNetworkManager:
    """
    Section 19: SystemNetworkManager Abstraction.
    Handles OS-level Proxy and DNS changes cleanly without polluting the Composition Root.
    Section 87: Ensures deterministic cleanup and crash recovery.
    """
    def __init__(self, state_file: str):
        self.state_file = state_file
        self.system = platform.system().lower()




    def load_state(self) -> dict:
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f: return json.load(f)
            except Exception: return {}
        return {}

    def save_state(self, state: dict):
        tmp_path = self.state_file + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=4)
            os.replace(tmp_path, self.state_file)
        except Exception as e:
            logger.error(f"Failed to write state file: {e}")

    async def restore_system_state(self):
        """Unified recovery for both Proxy and DNS (HANDOFF Sec 20)."""
        state = self.load_state()
        if state.get('proxy_backed_up'): await self.restore_system_proxy()
        if state.get('dns_changed'): await self.restore_system_dns()




    async def get_default_interface(self) -> str:
        if self.system == 'windows':
            proc = await asyncio.create_subprocess_exec('powershell', '-Command', 'Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -ExpandProperty InterfaceAlias', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await proc.communicate(); return stdout.decode().strip().split('\n')[0].strip()
        else:
            proc = await asyncio.create_subprocess_exec('ip', 'route', 'show', 'default', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, _ = await proc.communicate(); output = stdout.decode().strip()
            return output.split("dev")[1].split()[0] if "dev" in output else "eth0"

    def _extract_dns_ips(self, text: str) -> List[str]:
        ips = []
        for token in re.findall(r'[^\s,;]+', text):
            try: ipaddress.ip_address(token); ips.append(token)
            except ValueError: pass
        return ips

    async def get_current_dns(self) -> str:
        interface = await self.get_default_interface()
        try:
            if self.system == 'windows':
                p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'show', 'dns', f'name="{interface}"', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, _ = await p.communicate(); return json.dumps({"servers": self._extract_dns_ips(stdout.decode())})
            else: return "EMPTY"
        except Exception: return "EMPTY"

    async def restore_system_dns(self) -> bool:
        state = self.load_state()
        if not state.get('dns_changed'): return True
        interface = state.get('interface') or await self.get_default_interface()
        original_dns = state.get('original_dns', "")
        
        try:
            if self.system == 'windows':
                if not original_dns or "DHCP" not in original_dns:
                    p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'set', 'dns', f'name="{interface}"', 'source=dhcp', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p.communicate()
                else:

                    pass
                p_flush = await asyncio.create_subprocess_exec('ipconfig', '/flushdns', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p_flush.communicate()
            
            state['dns_changed'] = False; self.save_state(state)
            logger.info("System DNS restored to original settings.")
            return True
        except Exception as e:
            logger.error(f"DNS restore error: {e}"); return False

    async def set_system_dns(self, dns_list: List[str]):
        """Sets system DNS to the provided list (e.g., fastest scanned DNS)."""
        interface = await self.get_default_interface()
        state = self.load_state()
        
        if not state.get('dns_changed'):
            state['original_dns'] = await self.get_current_dns()
            state['interface'] = interface
            state['dns_changed'] = True
            self.save_state(state)
            
        try:
            if self.system == 'windows' and dns_list:
                p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'set', 'dns', f'name="{interface}"', 'static', dns_list[0], 'primary', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p.communicate()
                for ip in dns_list[1:]:
                    p = await asyncio.create_subprocess_exec('netsh', 'interface', 'ip', 'add', 'dns', f'name="{interface}"', ip, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); await p.communicate()
                logger.info(f"System DNS set to: {', '.join(dns_list)}")
            return True
        except Exception as e:
            logger.error(f"Set DNS error: {e}"); return False




    async def get_current_proxy(self) -> dict:
        try:
            if self.system == 'windows':
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, winreg.KEY_READ)
                enable, _ = winreg.QueryValueEx(key, 'ProxyEnable'); server = ""
                try: server, _ = winreg.QueryValueEx(key, 'ProxyServer')
                except: pass
                winreg.CloseKey(key); return {"valid": True, "enabled": bool(enable), "server": server}
            else: return {"valid": False, "enabled": False, "server": ""}
        except Exception: return {"valid": False, "enabled": False, "server": ""}

    async def restore_system_proxy(self) -> bool:
        state = self.load_state()
        if not state.get('proxy_backed_up'): return True
        original = state.get('original_proxy', {})
        if not original.get("valid"): return False
        
        try:
            if self.system == 'windows':
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, winreg.KEY_ALL_ACCESS)
                if original.get("enabled"): winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
                else: winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
                if original.get("server"): winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, original["server"])
                winreg.CloseKey(key)
                ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0); ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
            
            state['proxy_backed_up'] = False; state['proxy_enabled'] = original.get("enabled", False); self.save_state(state)
            logger.info("System proxy restored to original settings.")
            return True
        except Exception as e:
            logger.error(f"Proxy restore error: {e}"); return False

    async def set_system_proxy(self, enable: bool, port: int) -> bool:
        try:
            if self.system == 'windows':
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, winreg.KEY_ALL_ACCESS)
                if enable:
                    winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, f'127.0.0.1:{port}')
                    winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, 'localhost;127.0.0.1;<local>')
                else:
                    winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
                ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0); ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
            
            state = self.load_state(); state['proxy_enabled'] = enable; self.save_state(state)
            return True
        except Exception as e:
            logger.error(f"Set proxy error: {e}")
            return False