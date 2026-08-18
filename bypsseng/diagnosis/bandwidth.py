import asyncio
import time
import statistics
import aiohttp
from core.logger import log
from core.network import get_resolver
from config.models import CONFIG
from engine.models import DiagnosisResult

speed_test_sem = asyncio.Semaphore(3)

async def test_throttling():
    log("Phase 5: Checking Bandwidth...", "HEADER")
    
    resolver = get_resolver(nameservers=["1.1.1.1", "8.8.8.8"])
    connector = aiohttp.TCPConnector(resolver=resolver, limit=5)

    async def download_test(url, session):
        async with speed_test_sem:
            try:
                start = time.time(); downloaded = 0
                async with session.get(url) as response:
                    response.raise_for_status()
                    async for chunk in response.content.iter_chunked(8192):
                        downloaded += len(chunk)
                        if downloaded >= CONFIG.thresholds.speed_test_bytes or (time.time() - start) >= CONFIG.thresholds.speed_test_max_duration: break
                return (downloaded * 8 / 1000) / (time.time() - start) if downloaded > 0 else 0
            except Exception as e:
                import logging
                logging.getLogger("NetAnalyzer").debug(f"Download test error on {url}: {e}")
                return 0

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=CONFIG.intervals.http_timeout), connector=connector) as session:
        nat_speeds = await asyncio.gather(*[download_test(nat_url, session) for nat_url in CONFIG.targets.national_speed_urls for _ in range(CONFIG.thresholds.speed_test_samples)])
        int_speeds = await asyncio.gather(*[download_test(int_url, session) for int_url in CONFIG.targets.international_speed_urls for _ in range(CONFIG.thresholds.speed_test_samples)])
        
        nat_speed = statistics.median([s for s in nat_speeds if s > 0]) if any(nat_speeds) else 0
        int_speed = statistics.median([s for s in int_speeds if s > 0]) if any(int_speeds) else 0
        
        if int_speed == 0 and nat_speed > 0: 
            return DiagnosisResult(condition="intl_cut", confidence=0.9, evidence=["int_speed_0", "nat_speed_ok"], severity="high")
        if int_speed == 0 and nat_speed == 0: 
            return DiagnosisResult(condition="speed_failed", confidence=0.9, evidence=["int_speed_0", "nat_speed_0"], severity="critical")
        if int_speed < CONFIG.thresholds.speed_kbps_severe and nat_speed > int_speed * 3: 
            return DiagnosisResult(condition="throttled_intl", confidence=0.85, evidence=["int_speed_severe", "nat_speed_high"], severity="high")
        elif int_speed < CONFIG.thresholds.speed_kbps_slow: 
            return DiagnosisResult(condition="speed_slow", confidence=0.75, evidence=["int_speed_slow"], severity="medium")
        
        return DiagnosisResult(condition="speed_ok", confidence=1.0, evidence=[], severity="none")
