import asyncio
import time
import random
import ssl
import aiohttp
import logging
from core.logger import log
from core.network import get_resolver
from config.models import CONFIG

async def check_direct_health():
    log("Running strict direct health check (HTTPS & Anti-Blockpage)...", "INFO")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"}
    try:
        resolver = get_resolver(nameservers=["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        connector = aiohttp.TCPConnector(force_close=True, enable_cleanup_closed=True, resolver=resolver)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), headers=headers, trust_env=False, connector=connector) as session:
            checks_passed = 0
            checks_total = 0

            checks_total += 1
            try:
                async with session.get("https://www.google.com/generate_204", allow_redirects=False) as resp:
                    body = await resp.read()
                    location = resp.headers.get("Location", "")
                    if resp.status in (200, 204) and len(body) == 0:
                        checks_passed += 1
                    elif resp.status in (301, 302) and ("consent.google.com" in location or "www.google.com" in location):
                        checks_passed += 1
                    elif "10.10.34.34" in location or resp.status in (403, 451):
                        log("  -> Google generate_204: BLOCKED", "WARN")
                    else:
                        log(f"  -> Google generate_204: Unexpected status {resp.status}", "WARN")
            except Exception as e:
                log(f"  -> Google generate_204: Failed ({type(e).__name__})", "WARN")

            checks_total += 1
            try:
                async with session.get("https://www.youtube.com/generate_204", allow_redirects=False) as resp:
                    body = await resp.read()
                    location = resp.headers.get("Location", "")
                    if resp.status in (200, 204) and len(body) == 0:
                        checks_passed += 1
                    elif resp.status in (301, 302) and ("consent.google.com" in location or "www.google.com" in location):
                        checks_passed += 1
                    elif "10.10.34.34" in location or resp.status in (403, 451):
                        log("  -> YouTube generate_204: BLOCKED", "WARN")
                    else:
                        log(f"  -> YouTube generate_204: Unexpected status {resp.status}", "WARN")
            except Exception as e:
                log(f"  -> YouTube generate_204: Failed ({type(e).__name__})", "WARN")

            checks_total += 1
            try:
                async with session.get("https://1.1.1.1/cdn-cgi/trace") as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if "ip=" in text:
                            checks_passed += 1
            except Exception as e:
                log(f"  -> Cloudflare trace: Failed ({type(e).__name__})", "WARN")

            if checks_passed >= 2:
                log(f"  -> Direct health check: PASSED ({checks_passed}/{checks_total})", "PASS")
                return True
            else:
                log(f"  -> Direct health check: FAILED ({checks_passed}/{checks_total})", "WARN")
                return False
    except Exception as e:
        import logging
        logging.getLogger("NetAnalyzer").error(f"Direct health check session error: {e}")
    return False

async def check_captive_portal():
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.get(CONFIG.targets.captive_portal_url) as resp:
                text = await resp.text()
                return "success" not in text
    except Exception as e:
        import logging
        logging.getLogger("NetAnalyzer").debug(f"Captive portal check error: {e}")
        return False

async def check_geolocation():
    resolver = get_resolver(nameservers=["1.1.1.1", "8.8.8.8"])
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
                import logging
                logging.getLogger("NetAnalyzer").debug(f"ipinfo.io failed: {e}")

            if country == 'Unknown':
                try:
                    async with session.get("https://api.country.is/") as resp:
                        data = await resp.json()
                        country = data.get('country', 'Unknown')
                except Exception as e:
                    logging.getLogger("NetAnalyzer").debug(f"api.country.is failed: {e}")

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
