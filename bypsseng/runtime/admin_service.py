import asyncio
import json
import os
import platform
import logging
from core.logger import log

logger = logging.getLogger("NetAnalyzer")

class AdminIPCServer:

    def __init__(self, port):
        self.port = port
        self.server = None

    async def handle_request(self, reader, writer):
        data = await reader.read(4096)
        try:
            req = json.loads(data.decode())
            action = req.get("action")
            
            if action == "set_proxy":
                import BypssEng
                await BypssEng.set_system_proxy(req.get("enable"), req.get("port"))
                writer.write(b'{"status": "success"}')
            elif action == "restore_proxy":
                import BypssEng
                await BypssEng.restore_system_proxy()
                writer.write(b'{"status": "success"}')
            else:
                writer.write(b'{"status": "error", "msg": "Unknown action"}')
        except Exception as e:
            writer.write(f'{{"status": "error", "msg": "{e}"}}'.encode())
        await writer.drain()
        writer.close()

    async def start(self):
        self.server = await asyncio.start_server(self.handle_request, '127.0.0.1', self.port)
        log(f"Admin IPC Server started securely on port {self.port}", "PASS")

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

class AdminIPCClient:
    def __init__(self, port):
        self.port = port

    async def send_command(self, action, data=None):
        req = {"action": action}
        if data: req.update(data)
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
            writer.write(json.dumps(req).encode())
            await writer.drain()
            response = await reader.read(4096)
            writer.close()
            return json.loads(response.decode())
        except Exception as e:
            return {"status": "error", "msg": str(e)}
