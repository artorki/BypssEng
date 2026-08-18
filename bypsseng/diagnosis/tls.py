import asyncio
import aiohttp
from core.logger import log
from core.network import get_resolver
from config.models import CONFIG
from engine.models import DiagnosisResult

async def test_dpi_layer():
    import logging
    logger = logging.getLogger("NetAnalyzer")
    log("Phase 4: Checking Deep Packet Inspection (Behavioral & SNI)...", "HEADER")
    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"}
    targets = {
        "youtube": "https://www.youtube.com/generate_204",
        "google": "https://www.google.com/generate_204"
    }
    
    results = {}
    resolver = get_resolver(nameservers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    connector = aiohttp.TCPConnector(force_close=True, enable_cleanup_closed=True, resolver=resolver)
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), headers=headers, trust_env=False, connector=connector) as session:
        for name, url in targets.items():
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    body = await resp.read()
                    loc = resp.headers.get("Location", "")
                    
                    if name == "youtube":
                        log(f"  -> YouTube DPI: Status={resp.status}, Loc={loc}", "INFO")
                        if resp.status in (200, 204) and len(body) == 0:
                            results[name] = 'ok'
                        elif resp.status in (301, 302) and ("consent.google.com" in loc or "www.google.com" in loc):
                            results[name] = 'ok'
                        elif "10.10.34.34" in loc or (b'filter' in body.lower() and b'blocked' in body.lower()):
                            results[name] = 'blocked'
                        else:
                            results[name] = 'unknown'
                    elif name == "google":
                        log(f"  -> Google DPI: Status={resp.status}, Loc={loc}", "INFO")
                        if resp.status in (200, 204) and len(body) == 0:
                            results[name] = 'ok'
                        elif resp.status in (301, 302) and "consent.google.com" in loc:
                            results[name] = 'ok'
                        else:
                            results[name] = 'unknown'
            except asyncio.TimeoutError:
                log(f"  -> {name} DPI Test: Timeout", "WARN")
                results[name] = 'timeout'
            except aiohttp.ClientConnectorError as e:
                log(f"  -> {name} DPI Test: Connection Error: {e}", "WARN")
                results[name] = 'unknown'
            except Exception as e:
                logger.debug(f"DPI test error for {url}: {e}")
                results[name] = 'unknown'
                
    ggl_res = results.get("google")
    yt_res = results.get("youtube")
    
    if ggl_res == 'ok':
        if yt_res == 'blocked':
            return DiagnosisResult(condition="dpi_rst", confidence=0.85, evidence=["google_ok", "youtube_blocked"], severity="high")
        elif yt_res == 'ok':
            return DiagnosisResult(condition="dpi_none", confidence=1.0, evidence=[], severity="none")
        return DiagnosisResult(condition="dpi_unknown", confidence=0.5, evidence=["unspecified_error"], severity="low")
        
    if ggl_res in ('blocked', 'unknown', 'timeout') and yt_res in ('blocked', 'unknown', 'timeout'):
        return DiagnosisResult(condition="dpi_aggressive", confidence=0.90, evidence=["google_blocked", "youtube_blocked"], severity="critical")
        
    return DiagnosisResult(condition="dpi_unknown", confidence=0.5, evidence=["unspecified_error"], severity="low")
