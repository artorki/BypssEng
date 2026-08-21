


import asyncio
import json
import os
import time
import logging
from typing import Optional, Dict, Any, Callable
from core.logger import log

logger = logging.getLogger("NetAnalyzer")

class AdminIPCServer:
    """
    Authenticated local IPC for privilege separation (HANDOFF Sec 8, 41, 64).
    Features: Command Allowlist, Schema Validation, Rate Limiting, Audit Logging, Auth Token.
    """
    def __init__(self, port: int, network_manager, auth_token: Optional[str] = None):
        self.port = port

        self.network_manager = network_manager
        self.server = None
        

        self.auth_token = auth_token or os.urandom(16).hex()
        

        self.command_allowlist = {
            "set_proxy": self._handle_set_proxy,
            "restore_proxy": self._handle_restore_proxy,
            "set_dns": self._handle_set_dns,
            "restore_dns": self._handle_restore_dns
        }
        

        self._rate_limiter: Dict[str, float] = {}
        self._rate_limit_seconds = 1  # Max 1 request per second per IP

    async def handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peername = writer.get_extra_info('peername')
        ip_addr = peername[0] if peername else "Unknown"
        

        last_req = self._rate_limiter.get(ip_addr, 0)
        if time.time() - last_req < self._rate_limit_seconds:
            logger.warning(f"[SECURITY] Rate limit exceeded for {ip_addr}")
            writer.write(b'{"status": "error", "msg": "Rate limit exceeded"}')
            await writer.drain()
            writer.close()
            return
        self._rate_limiter[ip_addr] = time.time()

        data = await reader.read(4096)
        try:
            req = json.loads(data.decode())
            

            if req.get("token") != self.auth_token:
                logger.error(f"[SECURITY] Unauthorized IPC attempt from {ip_addr}")
                writer.write(b'{"status": "error", "msg": "Unauthorized"}')
                await writer.drain()
                writer.close()
                return

            action = req.get("action")
            payload = req.get("data", {})


            handler = self.command_allowlist.get(action)
            if not handler:
                logger.error(f"[SECURITY] Unknown command '{action}' from {ip_addr}")
                writer.write(b'{"status": "error", "msg": "Command not allowed"}')
                await writer.drain()
                writer.close()
                return


            logger.info(f"[AUDIT] Admin IPC Request from {ip_addr}: {action}")
            result = await handler(payload)
            
            writer.write(json.dumps({"status": "success", "data": result}).encode())
            
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON payload from {ip_addr}")
            writer.write(b'{"status": "error", "msg": "Invalid JSON"}')
        except Exception as e:
            logger.error(f"Admin IPC error from {ip_addr}: {e}")
            writer.write(f'{{"status": "error", "msg": "{e}"}}'.encode())
        finally:
            await writer.drain()
            writer.close()




    async def _handle_set_proxy(self, data: Dict[str, Any]):
        if "enable" not in data or "port" not in data:
            raise ValueError("Missing 'enable' or 'port' in set_proxy payload")
        return await self.network_manager.set_system_proxy(data["enable"], data["port"])

    async def _handle_restore_proxy(self, data: Dict[str, Any]):
        return await self.network_manager.restore_system_proxy()

    async def _handle_set_dns(self, data: Dict[str, Any]):
        if "dns" not in data:
            raise ValueError("Missing 'dns' in set_dns payload")
        return await self.network_manager.set_system_dns(data["dns"])

    async def _handle_restore_dns(self, data: Dict[str, Any]):
        return await self.network_manager.restore_system_dns()

    async def start(self):
        self.server = await asyncio.start_server(self.handle_request, '127.0.0.1', self.port)
        log(f"Admin IPC Server started securely on port {self.port}", "PASS")
        return self.auth_token  # Return token to be passed to the client/UI

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


class AdminIPCClient:
    """Client used by the UI/Dashboard to send secure commands to the Admin service."""
    def __init__(self, port: int, auth_token: str):
        self.port = port
        self.auth_token = auth_token

    async def send_command(self, action: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        req = {"action": action, "data": data or {}, "token": self.auth_token}
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
            writer.write(json.dumps(req).encode())
            await writer.drain()
            response = await reader.read(4096)
            writer.close()
            return json.loads(response.decode())
        except Exception as e:
            return {"status": "error", "msg": str(e)}