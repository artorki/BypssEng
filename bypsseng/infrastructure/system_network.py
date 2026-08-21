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
    def __init__(self, state_file: str):
        self.state_file = state_file
        self.system = platform.system().lower()

    def load_state(self) -> dict:
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
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

        state = self.load_state()
        if state.get("proxy_backed_up"):
            await self.restore_system_proxy()
        if state.get("dns_changed"):
            await self.restore_system_dns()

    async def get_default_interface(self) -> str:
        if self.system == "windows":
            proc = await asyncio.create_subprocess_exec(
                "powershell",
                "-Command",
                "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -ExpandProperty InterfaceAlias",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip().split("\n")[0].strip()
        elif self.system == "darwin":
            try:
                route_proc = await asyncio.create_subprocess_exec(
                    "route",
                    "-n",
                    "get",
                    "default",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout, _ = await route_proc.communicate()
                output = stdout.decode()
                iface = "en0"
                if "interface:" in output:
                    iface = output.split("interface:")[1].split()[0]
                svc_proc = await asyncio.create_subprocess_exec(
                    "networksetup",
                    "-listallhardwareports",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout, _ = await svc_proc.communicate()
                lines = stdout.decode().splitlines()
                current_hw = None
                for line in lines:
                    if "Hardware Port:" in line:
                        current_hw = line.replace("Hardware Port: ", "").strip()
                    elif "Device: " + iface in line:
                        return current_hw
                return "Wi-Fi"
            except Exception:
                return "Wi-Fi"
        else:
            proc = await asyncio.create_subprocess_exec(
                "ip",
                "route",
                "show",
                "default",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode().strip()
            return output.split("dev")[1].split()[0] if "dev" in output else "eth0"

    def _extract_dns_ips(self, text: str) -> List[str]:
        ips = []
        for line in text.splitlines():
            if (
                "DNS Servers" in line
                or "Statically Configured DNS" in line
                or "Dynamically Configured DNS" in line
            ):
                for token in re.findall(r"[^\s,;]+", line):
                    try:
                        ipaddress.ip_address(token)
                        ips.append(token)
                    except ValueError:
                        pass
        if not ips:
            for token in re.findall(r"[^\s,;]+", text):
                try:
                    ipaddress.ip_address(token)
                    ips.append(token)
                except ValueError:
                    pass
        return ips

    async def get_current_dns(self) -> str:
        interface = await self.get_default_interface()
        try:
            if self.system == "windows":
                v4_out = ""
                v6_out = ""
                try:
                    p1 = await asyncio.create_subprocess_exec(
                        "netsh",
                        "interface",
                        "ip",
                        "show",
                        "dns",
                        f'name="{interface}"',
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    stdout, _ = await p1.communicate()
                    v4_out = stdout.decode()
                except:
                    pass
                try:
                    p2 = await asyncio.create_subprocess_exec(
                        "netsh",
                        "interface",
                        "ipv6",
                        "show",
                        "dns",
                        f'name="{interface}"',
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    stdout, _ = await p2.communicate()
                    v6_out = stdout.decode()
                except:
                    pass
                return json.dumps(
                    {
                        "v4_mode": "DHCP" if "DHCP" in v4_out else "STATIC",
                        "v4_servers": self._extract_dns_ips(v4_out),
                        "v6_mode": "DHCP" if "DHCP" in v6_out else "STATIC",
                        "v6_servers": self._extract_dns_ips(v6_out),
                    }
                )
            elif self.system == "darwin":
                proc = await asyncio.create_subprocess_exec(
                    "networksetup",
                    "-getdnsservers",
                    interface,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                out = stdout.decode().strip()
                return out if out else "EMPTY"
            else:
                if shutil.which("resolvectl"):
                    proc = await asyncio.create_subprocess_exec(
                        "resolvectl",
                        "dns",
                        interface,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    stdout, _ = await proc.communicate()
                    out = stdout.decode().strip()
                    ips = self._extract_dns_ips(out)
                    return " ".join(ips) if ips else "EMPTY"
                return "EMPTY"
        except Exception:
            return "EMPTY"

    async def restore_system_dns(self) -> bool:
        state = self.load_state()
        if not state.get("dns_changed"):
            return True
        interface = state.get("interface") or await self.get_default_interface()
        original_dns = state.get("original_dns", "")

        try:
            if self.system == "windows":
                try:
                    dns_data = json.loads(original_dns)
                except Exception:
                    state["dns_changed"] = False
                    state["dns_backed_up"] = False
                    self.save_state(state)
                    return False
                if dns_data.get("v4_mode") == "DHCP":
                    p = await asyncio.create_subprocess_exec(
                        "netsh",
                        "interface",
                        "ip",
                        "set",
                        "dns",
                        f'name="{interface}"',
                        "source=dhcp",
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    await p.communicate()
                else:
                    v4_ips = dns_data.get("v4_servers", [])
                    if v4_ips:
                        p = await asyncio.create_subprocess_exec(
                            "netsh",
                            "interface",
                            "ip",
                            "set",
                            "dns",
                            f'name="{interface}"',
                            "static",
                            v4_ips[0],
                            "primary",
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        await p.communicate()
                        for i, ip in enumerate(v4_ips[1:], start=2):
                            p = await asyncio.create_subprocess_exec(
                                "netsh",
                                "interface",
                                "ip",
                                "add",
                                "dns",
                                f'name="{interface}"',
                                ip,
                                f"index={i}",
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                            )
                            await p.communicate()
                p_flush = await asyncio.create_subprocess_exec(
                    "ipconfig",
                    "/flushdns",
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                await p_flush.communicate()
            elif self.system == "darwin":
                if original_dns and "There aren't any DNS Servers" not in original_dns:
                    dns_list = original_dns.split()
                    p = await asyncio.create_subprocess_exec(
                        "networksetup",
                        "-setdnsservers",
                        interface,
                        *dns_list,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    await p.communicate()
                else:
                    p = await asyncio.create_subprocess_exec(
                        "networksetup",
                        "-setdnsservers",
                        interface,
                        "empty",
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    await p.communicate()
            else:
                if shutil.which("resolvectl"):
                    if original_dns and original_dns != "EMPTY":
                        dns_ips = original_dns.split()
                        p = await asyncio.create_subprocess_exec(
                            "resolvectl",
                            "dns",
                            interface,
                            *dns_ips,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        await p.communicate()
                    else:
                        p = await asyncio.create_subprocess_exec(
                            "resolvectl",
                            "revert",
                            interface,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        await p.communicate()
            state["dns_changed"] = False
            state["dns_backed_up"] = False
            state.pop("original_dns", None)
            self.save_state(state)
            logger.info("System DNS restored to original settings.")
            return True
        except Exception as e:
            logger.error(f"DNS restore error: {e}")
            return False

    async def set_system_dns(self, dns_list: List[str]):

        interface = await self.get_default_interface()
        state = self.load_state()

        if not state.get("dns_changed"):
            state["original_dns"] = await self.get_current_dns()
            state["interface"] = interface
            state["dns_changed"] = True
            self.save_state(state)

        try:
            if self.system == "windows" and dns_list:
                p = await asyncio.create_subprocess_exec(
                    "netsh",
                    "interface",
                    "ip",
                    "set",
                    "dns",
                    f'name="{interface}"',
                    "static",
                    dns_list[0],
                    "primary",
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                await p.communicate()
                for ip in dns_list[1:]:
                    p = await asyncio.create_subprocess_exec(
                        "netsh",
                        "interface",
                        "ip",
                        "add",
                        "dns",
                        f'name="{interface}"',
                        ip,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    await p.communicate()
                logger.info(f"System DNS set to: {', '.join(dns_list)}")
            return True
        except Exception as e:
            logger.error(f"Set DNS error: {e}")
            return False

    async def get_current_proxy(self) -> dict:
        try:
            if self.system == "windows":
                import winreg

                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0,
                    winreg.KEY_READ,
                )
                enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                server = ""
                override = ""
                try:
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                except:
                    pass
                try:
                    override, _ = winreg.QueryValueEx(key, "ProxyOverride")
                except:
                    pass
                winreg.CloseKey(key)
                return {
                    "valid": True,
                    "enabled": bool(enable),
                    "server": server,
                    "override": override,
                }
            elif self.system == "darwin":
                interface = await self.get_default_interface()
                proc = await asyncio.create_subprocess_exec(
                    "networksetup",
                    "-getwebproxy",
                    interface,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                out = stdout.decode()
                enabled = "Enabled: Yes" in out
                server = re.search(r"Server: (\S+)", out)
                port = re.search(r"Port: (\d+)", out)
                sproc = await asyncio.create_subprocess_exec(
                    "networksetup",
                    "-getsecurewebproxy",
                    interface,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                sout, _ = await sproc.communicate()
                sout_str = sout.decode()
                s_enabled = "Enabled: Yes" in sout_str
                s_server = re.search(r"Server: (\S+)", sout_str)
                s_port = re.search(r"Port: (\d+)", sout_str)
                return {
                    "valid": True,
                    "web_enabled": enabled,
                    "secure_enabled": s_enabled,
                    "server": (
                        f"{server.group(1)}:{port.group(1)}" if server and port else ""
                    ),
                    "secure_server": (
                        f"{s_server.group(1)}:{s_port.group(1)}"
                        if s_server and s_port
                        else ""
                    ),
                }
            else:
                if not shutil.which("gsettings"):
                    return {"valid": False, "enabled": False, "server": ""}
                mode_proc = await asyncio.create_subprocess_exec(
                    "gsettings",
                    "get",
                    "org.gnome.system.proxy",
                    "mode",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout, _ = await mode_proc.communicate()
                mode = stdout.decode().strip().strip("'")
                if mode == "manual":
                    host_proc = await asyncio.create_subprocess_exec(
                        "gsettings",
                        "get",
                        "org.gnome.system.proxy.http",
                        "host",
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    host, _ = await host_proc.communicate()
                    port_proc = await asyncio.create_subprocess_exec(
                        "gsettings",
                        "get",
                        "org.gnome.system.proxy.http",
                        "port",
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    port, _ = await port_proc.communicate()
                    http_host = host.decode().strip().strip("'")
                    return {
                        "valid": True,
                        "enabled": True,
                        "server": (
                            f"{http_host}:{port.decode().strip().strip(chr(39))}"
                            if http_host
                            else ""
                        ),
                    }
                return {"valid": True, "enabled": False, "server": ""}
        except Exception:
            return {"valid": False, "enabled": False, "server": ""}

    async def restore_system_proxy(self) -> bool:
        state = self.load_state()
        if not state.get("proxy_backed_up"):
            return True
        original = state.get("original_proxy", {})
        if not original.get("valid"):
            return False

        try:
            if self.system == "windows":
                import winreg

                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0,
                    winreg.KEY_ALL_ACCESS,
                )
                if original.get("enabled"):
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                else:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                if original.get("server"):
                    winreg.SetValueEx(
                        key, "ProxyServer", 0, winreg.REG_SZ, original["server"]
                    )
                winreg.CloseKey(key)
                ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)
                ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
            elif self.system == "darwin":
                interface = await self.get_default_interface()
                if original.get("web_enabled") and original.get("server"):
                    host, port = original["server"].rsplit(":", 1)
                    host = host.strip("[]")
                    p = await asyncio.create_subprocess_exec(
                        "networksetup",
                        "-setwebproxy",
                        interface,
                        host,
                        port,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    await p.communicate()
                else:
                    p = await asyncio.create_subprocess_exec(
                        "networksetup",
                        "-setwebproxystate",
                        interface,
                        "off",
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    await p.communicate()
            else:
                if not shutil.which("gsettings"):
                    return False
                cmds = (
                    [["gsettings", "set", "org.gnome.system.proxy", "mode", "none"]]
                    if not original.get("enabled")
                    else [
                        ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"]
                    ]
                )
                for cmd in cmds:
                    p = await asyncio.create_subprocess_exec(
                        *cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    await p.communicate()
            state["proxy_backed_up"] = False
            state["proxy_enabled"] = original.get("enabled", False)
            state.pop("original_proxy", None)
            self.save_state(state)
            logger.info("System proxy restored to original settings.")
            return True
        except Exception as e:
            logger.error(f"Proxy restore error: {e}")
            return False

    async def set_system_proxy(self, enable: bool, port: int = None) -> bool:

        try:
            if self.system == "windows":
                import winreg

                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0,
                    winreg.KEY_ALL_ACCESS,
                )
                if enable:
                    if not port:
                        raise ValueError("Port is required when enabling proxy")
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(
                        key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}"
                    )
                    winreg.SetValueEx(
                        key,
                        "ProxyOverride",
                        0,
                        winreg.REG_SZ,
                        "localhost;127.0.0.1;<local>",
                    )
                else:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
                ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)
                ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
            elif self.system == "darwin":
                interface = await self.get_default_interface()
                if enable:
                    if not port:
                        raise ValueError("Port is required")
                    p1 = await asyncio.create_subprocess_exec(
                        "networksetup",
                        "-setwebproxy",
                        interface,
                        "127.0.0.1",
                        str(port),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    await p1.communicate()
                    p2 = await asyncio.create_subprocess_exec(
                        "networksetup",
                        "-setsecurewebproxy",
                        interface,
                        "127.0.0.1",
                        str(port),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    await p2.communicate()
                else:
                    p1 = await asyncio.create_subprocess_exec(
                        "networksetup",
                        "-setwebproxystate",
                        interface,
                        "off",
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    await p1.communicate()
                    p2 = await asyncio.create_subprocess_exec(
                        "networksetup",
                        "-setsecurewebproxystate",
                        interface,
                        "off",
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    await p2.communicate()
            else:
                if not shutil.which("gsettings"):
                    return False
                if enable:
                    if not port:
                        raise ValueError("Port is required")
                    cmds = [
                        [
                            "gsettings",
                            "set",
                            "org.gnome.system.proxy",
                            "mode",
                            "manual",
                        ],
                        [
                            "gsettings",
                            "set",
                            "org.gnome.system.proxy.http",
                            "host",
                            "127.0.0.1",
                        ],
                        [
                            "gsettings",
                            "set",
                            "org.gnome.system.proxy.http",
                            "port",
                            str(port),
                        ],
                    ]
                else:
                    cmds = [
                        ["gsettings", "set", "org.gnome.system.proxy", "mode", "none"]
                    ]
                for cmd in cmds:
                    p = await asyncio.create_subprocess_exec(
                        *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                    await p.communicate()

            state = self.load_state()
            state["proxy_enabled"] = enable
            self.save_state(state)
            return True
        except Exception as e:
            logger.error(f"Set proxy error: {e}")
            return False
