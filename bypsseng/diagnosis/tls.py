


import asyncio
import time
import aiohttp
import logging
from core.logger import log
from core.network import get_resolver
from config.models import CONFIG
from bypsseng.domain.models import DiagnosisResult
from bypsseng.domain.conditions import NetworkCondition

logger = logging.getLogger("NetAnalyzer")

async def test_dpi_layer():
    """
    Behavioral DPI Test (Fallback for Kernel DPI).
    Section 23: Includes latency in evidence.
    Section 27: Returns dpi_unknown for conflicting observations.
    """
    log("Phase 4: Checking Deep Packet Inspection (Behavioral & SNI)...", "HEADER")
    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"}
    targets = {
        "youtube": "https://www.youtube.com/generate_204",
        "google": "https://www.google.com/generate_204"
    }
    
    results = {}
    resolver = get_resolver(nameservers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    connector = aiohttp.TCPConnector(force_close=True, enable_cleanup_closed=True, resolver=resolver)
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), headers=headers, trust_env=False, connector=connector) as session:
            for name, url in targets.items():
                try:
                    start = time.time()
                    async with session.get(url, allow_redirects=False) as resp:
                        latency = round((time.time() - start) * 1000, 2)
                        body = await resp.read()
                        loc = resp.headers.get("Location", "")
                        
                        if name == "youtube":
                            if resp.status in (200, 204) and len(body) == 0:
                                results[name] = {'status': 'ok', 'latency': latency}
                            elif resp.status in (301, 302) and ("consent.google.com" in loc or "www.google.com" in loc):
                                results[name] = {'status': 'ok', 'latency': latency}
                            elif "10.10.34.34" in loc or (b'filter' in body.lower() and b'blocked' in body.lower()):
                                results[name] = {'status': 'blocked', 'latency': latency, 'code': resp.status}
                            else:
                                results[name] = {'status': 'unknown', 'latency': latency, 'code': resp.status}
                        elif name == "google":
                            if resp.status in (200, 204) and len(body) == 0:
                                results[name] = {'status': 'ok', 'latency': latency}
                            elif resp.status in (301, 302) and "consent.google.com" in loc:
                                results[name] = {'status': 'ok', 'latency': latency}
                            else:
                                results[name] = {'status': 'unknown', 'latency': latency, 'code': resp.status}
                except asyncio.TimeoutError:
                    results[name] = {'status': 'timeout', 'latency': None}
                except aiohttp.ClientConnectorError as e:
                    results[name] = {'status': 'error', 'latency': None, 'msg': str(e)}
                except Exception as e:
                    logger.debug(f"DPI test error for {url}: {e}")
                    results[name] = {'status': 'unknown', 'latency': None}
                
        ggl_res = results.get("google", {}).get('status', 'unknown')
        yt_res = results.get("youtube", {}).get('status', 'unknown')
        

        evidence = [
            f"google={ggl_res}({results.get('google', {}).get('latency', 'N/A')}ms)",
            f"youtube={yt_res}({results.get('youtube', {}).get('latency', 'N/A')}ms)"
        ]
        

        if ggl_res == 'ok':
            if yt_res == 'blocked':
                return DiagnosisResult(
                    condition=NetworkCondition.DPI_RST.value, 
                    confidence=0.85, 
                    evidence=evidence + ["google_ok", "youtube_blocked"], 
                    severity="high"
                )
            elif yt_res == 'ok':
                return DiagnosisResult(
                    condition=NetworkCondition.DPI_NONE.value, 
                    confidence=1.0, 
                    evidence=evidence, 
                    severity="none"
                )
            

        if ggl_res in ('blocked', 'unknown', 'timeout', 'error') and yt_res in ('blocked', 'unknown', 'timeout', 'error'):
            return DiagnosisResult(
                condition=NetworkCondition.DPI_AGGRESSIVE.value, 
                confidence=0.90, 
                evidence=evidence + ["google_blocked", "youtube_blocked"], 
                severity="critical"
            )
            
        return DiagnosisResult(
            condition=NetworkCondition.DPI_UNKNOWN.value, 
            confidence=0.5, 
            evidence=evidence + ["unspecified_error"], 
            severity="low"
        )
    except Exception as e:
        logger.error(f"DPI test critical error: {e}")
        return DiagnosisResult(
            condition=NetworkCondition.DPI_UNKNOWN.value, 
            confidence=0.5, 
            evidence=[f"error={str(e)}"], 
            severity="low"
        )