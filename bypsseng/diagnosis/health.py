


import asyncio
import time
import random
import ssl
import aiohttp
import logging
from core.logger import log
from config.models import CONFIG
from bypsseng.domain.models import DiagnosisResult
from bypsseng.domain.conditions import NetworkCondition

logger = logging.getLogger("NetAnalyzer")

async def check_direct_health():
    """
    Section 23 & 40: Returns detailed health status of each endpoint.
    Helps prevent false-positives in selective filtering (e.g., YouTube blocked, Google open).
    """
    log("Running strict direct health check (HTTPS & Anti-Blockpage)...", "INFO")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"}
    
    resolver = __import__('core.network', fromlist=['get_resolver']).get_resolver(nameservers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    connector = aiohttp.TCPConnector(force_close=True, enable_cleanup_closed=True, resolver=resolver)
    results = {}
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), headers=headers, trust_env=False, connector=connector) as session:
            

            try:
                start = time.time()
                async with session.get("https://www.google.com/generate_204", allow_redirects=False) as resp:
                    latency = round((time.time() - start) * 1000, 2)
                    if resp.status in (200, 204):
                        results['google'] = {'status': 'ok', 'latency': latency}
                    elif resp.status in (403, 451):
                        results['google'] = {'status': 'blocked', 'latency': latency, 'code': resp.status}
                    else:
                        results['google'] = {'status': 'unknown', 'latency': latency, 'code': resp.status}
            except Exception as e:
                results['google'] = {'status': 'error', 'latency': None, 'msg': str(e)}


            try:
                start = time.time()
                async with session.get("https://www.youtube.com/generate_204", allow_redirects=False) as resp:
                    latency = round((time.time() - start) * 1000, 2)
                    if resp.status in (200, 204):
                        results['youtube'] = {'status': 'ok', 'latency': latency}
                    elif resp.status in (403, 451):
                        results['youtube'] = {'status': 'blocked', 'latency': latency, 'code': resp.status}
                    else:
                        results['youtube'] = {'status': 'unknown', 'latency': latency, 'code': resp.status}
            except Exception as e:
                results['youtube'] = {'status': 'error', 'latency': None, 'msg': str(e)}


            try:
                start = time.time()
                async with session.get("https://1.1.1.1/cdn-cgi/trace") as resp:
                    latency = round((time.time() - start) * 1000, 2)
                    if resp.status == 200:
                        text = await resp.text()
                        if "ip=" in text:
                            results['cloudflare'] = {'status': 'ok', 'latency': latency}
                        else:
                            results['cloudflare'] = {'status': 'unknown', 'latency': latency}
                    else:
                        results['cloudflare'] = {'status': 'blocked', 'latency': latency, 'code': resp.status}
            except Exception as e:
                results['cloudflare'] = {'status': 'error', 'latency': None, 'msg': str(e)}


        ok_count = sum(1 for r in results.values() if r['status'] == 'ok')
        is_healthy = ok_count >= 2  # At least 2 out of 3 must be OK
        
        if is_healthy:
            log(f"  -> Direct health check: PASSED ({ok_count}/3)", "PASS")
        else:
            log(f"  -> Direct health check: FAILED ({ok_count}/3)", "WARN")
            for site, res in results.items():
                if res['status'] != 'ok':
                    logger.debug(f"  -> {site} failed: {res}")
                
        return is_healthy, results
    except Exception as e:
        logger.error(f"Direct health check critical error: {e}")
        return False, {"error": str(e)}

async def check_captive_portal():
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.get(CONFIG.targets.captive_portal_url) as resp:
                text = await resp.text()
                return "success" not in text
    except Exception as e:
        logger.debug(f"Captive portal check error: {e}")
        return False

async def check_geolocation():
    resolver = __import__('core.network', fromlist=['get_resolver']).get_resolver(nameservers=["1.1.1.1", "8.8.8.8"])
    try:
        timeout = aiohttp.ClientTimeout(total=8)
        connector = aiohttp.TCPConnector(resolver=resolver)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            country = 'Unknown'
            try:
                async with session.get("https://ipinfo.io/json") as resp:
                    data = await resp.json()
                    country = data.get('country', 'Unknown')
            except Exception as e:
                logger.debug(f"ipinfo.io failed: {e}")

            if country == 'Unknown':
                try:
                    async with session.get("https://api.country.is/") as resp:
                        data = await resp.json()
                        country = data.get('country', 'Unknown')
                except Exception as e:
                    logger.debug(f"api.country.is failed: {e}")

            if country == 'IR':
                log(f"Geolocation: {country}. Inside Iran network.", "WARN")
                return True
            elif country != 'Unknown':
                log(f"Geolocation: {country}. Already bypassing or outside Iran.", "PASS")
                return False
            else:
                log("Geolocation undetermined. Assuming inside Iran to run tests.", "WARN")
                return True
    except Exception as e:
        log(f"Geolocation check failed ({e}). Assuming inside Iran.", "WARN")
        return True

async def scan_clean_cdn_ips(cdn_provider="cloudflare", worker_host=None, worker_path="/", count=3):
    log(f"Scanning for clean {cdn_provider.capitalize()} IPs...", "SOL")
    
    def get_random_ip():
        if cdn_provider == "cloudflare":
            choice = random.choice(CONFIG.cdn_ranges.cloudflare)
            return f"{choice[0]}.{choice[1]}.{random.randint(0,255)}.{random.randint(0,255)}"
        elif cdn_provider == "gcore":
            choice = random.choice(CONFIG.cdn_ranges.gcore)
            return f"{choice[0]}.{choice[1]}.{random.randint(0,255)}.{random.randint(0,255)}"
        elif cdn_provider == "aws":
            return random.choice(CONFIG.cdn_ranges.aws)
        return "1.1.1.1"
    
    async def test_ip(ip):
        try:
            start = time.time()
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 443), timeout=2)
            latency = round((time.time() - start) * 1000, 2)
            writer.close()
            await writer.wait_closed()
            
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ssl_reader, ssl_writer = await asyncio.open_connection(host=ip, port=443, ssl=ctx, server_hostname=worker_host or 'speed.cloudflare.com')
            
            req = f"GET {worker_path} HTTP/1.1\r\nHost: {worker_host or 'speed.cloudflare.com'}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            ssl_writer.write(req.encode())
            await ssl_writer.drain()
            resp_data = await ssl_reader.read(1024)
            ssl_writer.close()
            await ssl_writer.wait_closed()
            
            if b"HTTP/1.1 101" in resp_data or b"HTTP/1.1 426" in resp_data or b"HTTP/1.1 400" in resp_data:
                return (ip, latency)
            return None
        except Exception:
            return None
    
    tasks = [test_ip(get_random_ip()) for _ in range(count * 5)]
    results = await asyncio.gather(*tasks)
    working_ips = [r for r in results if r is not None]
    working_ips.sort(key=lambda x: x[1])
    
    if working_ips:
        return [ip for ip, lat in working_ips[:count]]
    else:
        log(f"  -> No clean {cdn_provider} IP found in scan.", "WARN")
        return []