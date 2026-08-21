


import aiohttp
from aiohttp import web
import json
import os
import logging
import secrets
import asyncio


import telemetry.storage as telemetry
import BypssEng

logger = logging.getLogger("NetAnalyzer")

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "core", "index.html")


DASHBOARD_TOKEN = secrets.token_hex(16)

class WebSocketBroadcaster:
    def __init__(self): self.clients = set()
    def add_client(self, ws): self.clients.add(ws)
    def remove_client(self, ws): self.clients.discard(ws)
    async def broadcast(self, event_type, payload):
        dead_clients = set()
        for ws in self.clients:
            try: await ws.send_json({"type": event_type, "payload": payload})
            except Exception: dead_clients.add(ws)
        self.clients.difference_update(dead_clients)

broadcaster = WebSocketBroadcaster()

@web.middleware
async def auth_middleware(request, handler):

    if request.path.startswith('/api') or request.path == '/ws':
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token and request.path == '/ws': token = request.query.get('token', '')
        if token != DASHBOARD_TOKEN:
            logger.warning(f"[SECURITY] Unauthorized API attempt from {request.remote}")
            return web.json_response({"error": "Unauthorized"}, status=401)
    return await handler(request)

async def websocket_handler(request):
    ws = web.WebSocketResponse(); await ws.prepare(request); broadcaster.add_client(ws)
    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.ERROR:
                logger.error(f'WebSocket error: {ws.exception()}')
    finally:
        broadcaster.remove_client(ws)
    return ws

async def index_handler(request):
    if os.path.exists(INDEX_HTML_PATH): return web.FileResponse(INDEX_HTML_PATH)
    return web.Response(text=f"index.html not found at {INDEX_HTML_PATH}!", status=404)

async def get_status(request):

    state = BypssEng.load_state()
    report = {}
    if os.path.exists(BypssEng.REPORT_FILE):
        with open(BypssEng.REPORT_FILE, 'r') as f:
            report = json.load(f)
    return web.json_response({"state": state, "report": report})

async def get_logs(request):
    logs = await telemetry.db.get_recent_logs(100)
    return web.json_response(logs)

async def get_configs(request):

    cfg = BypssEng.load_unified_config()
    safe_configs = {
        "total_configs": len(cfg.get("configs", [])),
        "protocols": {},
        "has_warp": bool(cfg.get("warp")),
        "has_cloudflare_worker": bool(cfg.get("cloudflare_worker")),
        "subscription_urls": cfg.get("subscription_urls", [])
    }
    for link in cfg.get("configs", []):
        proto = link.split("://")[0] if "://" in link else "unknown"
        safe_configs["protocols"][proto] = safe_configs["protocols"].get(proto, 0) + 1
    return web.json_response(safe_configs)

async def get_history(request):
    history = await telemetry.db.get_history(50)
    return web.json_response(history)

async def get_decision_history_api(request):
    history = await telemetry.db.get_decision_history(50)
    return web.json_response(history)

async def test_config_api(request):
    data = await request.json(); link = data.get("link")
    if not link: return web.json_response({"error": "Link required"}, status=400)
    

    parsed = BypssEng.parse_config_link(link)
    if parsed["protocol"] == "unsupported":
        return web.json_response({"error": "Invalid or unsupported config"}, status=400)
        
    latency = await BypssEng.check_config_latency(parsed)
    return web.json_response({"parsed": {"protocol": parsed["protocol"]}, "latency": latency})

async def save_subscription(request):
    data = await request.json(); urls = data.get("urls", [])
    if not urls: return web.json_response({"error": "URLs required"}, status=400)
    
    cfg = BypssEng.load_unified_config(); cfg["subscription_urls"] = urls
    BypssEng.atomic_write_json(BypssEng.UNIFIED_CONFIG_FILE, cfg)
    

    asyncio.create_task(BypssEng.fetch_fresh_configs(wait=False))
    return web.json_response({"status": "success"})


async def export_diagnostics(request):
    diag_data = {
        "system_info": {
            "os": os.name,
            "python_version": sys.version
        },
        "network_report": {},
        "recent_logs": [],
        "decision_history": []
    }
    if os.path.exists(BypssEng.REPORT_FILE):
        with open(BypssEng.REPORT_FILE, 'r') as f:
            diag_data["network_report"] = json.load(f)
            
    diag_data["recent_logs"] = await telemetry.db.get_recent_logs(500)
    diag_data["decision_history"] = await telemetry.db.get_decision_history(500)
    
    return web.json_response(diag_data)

async def create_app():
    app = web.Application(middlewares=[auth_middleware])
    app.add_routes([
        web.get('/', index_handler),
        web.get('/ws', websocket_handler),
        web.get('/api/status', get_status),
        web.get('/api/logs', get_logs),
        web.get('/api/configs', get_configs),
        web.get('/api/history', get_history),
        web.get('/api/decision_history', get_decision_history_api),
        web.post('/api/configs/test', test_config_api),
        web.post('/api/configs/subscription', save_subscription),

        web.get('/api/diagnostics/export', export_diagnostics),
    ])
    return app