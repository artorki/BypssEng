


import asyncio
import time
import statistics
import aiohttp
import logging
from core.logger import log
from core.network import get_resolver
from config.models import CONFIG
from bypsseng.domain.models import DiagnosisResult
from bypsseng.domain.conditions import NetworkCondition

logger = logging.getLogger("NetAnalyzer")
speed_test_sem = asyncio.Semaphore(3)

async def test_throttling():
    """
    Measures national and international bandwidth.
    Section 23: Returns rich telemetry data (actual speeds) in evidence.
    Section 27: Returns speed_failed (insufficient data) if tests fail.
    """
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

                logger.debug(f"Download test error on {url}: {e}")
                return 0

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=CONFIG.intervals.http_timeout), connector=connector) as session:
            nat_speeds = await asyncio.gather(*[download_test(nat_url, session) for nat_url in CONFIG.targets.national_speed_urls for _ in range(CONFIG.thresholds.speed_test_samples)])
            int_speeds = await asyncio.gather(*[download_test(int_url, session) for int_url in CONFIG.targets.international_speed_urls for _ in range(CONFIG.thresholds.speed_test_samples)])
            
            nat_speed = statistics.median([s for s in nat_speeds if s > 0]) if any(nat_speeds) else 0
            int_speed = statistics.median([s for s in int_speeds if s > 0]) if any(int_speeds) else 0
            

            evidence = [f"nat_speed={nat_speed:.2f}kbps", f"int_speed={int_speed:.2f}kbps"]
            

            if int_speed == 0 and nat_speed > 0: 
                return DiagnosisResult(
                    condition=NetworkCondition.INTL_CUT.value, 
                    confidence=0.9, 
                    evidence=evidence + ["int_speed_0", "nat_speed_ok"], 
                    severity="high"
                )
            if int_speed == 0 and nat_speed == 0: 

                return DiagnosisResult(
                    condition=NetworkCondition.SPEED_FAILED.value, 
                    confidence=0.9, 
                    evidence=evidence + ["int_speed_0", "nat_speed_0"], 
                    severity="critical"
                )
            if int_speed < CONFIG.thresholds.speed_kbps_severe and nat_speed > int_speed * 3: 
                return DiagnosisResult(
                    condition=NetworkCondition.THROTTLED_INTL.value, 
                    confidence=0.85, 
                    evidence=evidence + ["int_speed_severe", "nat_speed_high"], 
                    severity="high"
                )
            elif int_speed < CONFIG.thresholds.speed_kbps_slow: 
                return DiagnosisResult(
                    condition=NetworkCondition.SPEED_SLOW.value, 
                    confidence=0.75, 
                    evidence=evidence + ["int_speed_slow"], 
                    severity="medium"
                )
            
            return DiagnosisResult(
                condition=NetworkCondition.SPEED_OK.value, 
                confidence=1.0, 
                evidence=evidence, 
                severity="none"
            )
    except Exception as e:
        logger.error(f"Bandwidth test critical error: {e}")
        return DiagnosisResult(
            condition=NetworkCondition.SPEED_FAILED.value, 
            confidence=0.9, 
            evidence=[f"error={str(e)}"], 
            severity="critical"
        )