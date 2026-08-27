import os
import sys
import time
import json
import random
import string
import base64
import uuid
import asyncio
import aiohttp
import socket
import ssl
import logging
import platform
from urllib.parse import urlparse, parse_qs, unquote

from core.utils import parse_config_link

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import serialization
except ImportError:
    logging.getLogger("ConfigFetcher").error("Error: 'cryptography' is not installed.")
    sys.exit(1)

logger = logging.getLogger("ConfigFetcher")

_PRIMARY_CONFIG_URLS = [
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/vless",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/trojan",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/mixed",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/vless",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/trojan",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2",
    "https://raw.githubusercontent.com/AzadNetCh/NetV2/main/qsub",
    "https://raw.githubusercontent.com/MrPooyaX/VpnsFucking/main/sub.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/splitted/mixed",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/merged"
]

def _github_mirror_urls(urls):

    prefix = "https://raw.githubusercontent.com/"
    mirrors = []
    for url in urls:
        if not url.startswith(prefix): continue
        parts = url[len(prefix):].split("/", 3)
        if len(parts) != 4: continue
        owner, repo, branch, path = parts
        mirrors.append(f"https://fastly.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}")
        mirrors.append(f"https://raw.githack.com/{owner}/{repo}/{branch}/{path}")
        mirrors.append(f"https://ghproxy.com/{url}")
    return mirrors

FREE_CONFIGS_URLS = _PRIMARY_CONFIG_URLS + _github_mirror_urls(_PRIMARY_CONFIG_URLS)

OUTPUT_FILE = "cnfg.json"

HARDCODED_DNS = {
    "raw.githubusercontent.com": ["185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133"],
    "cdn.jsdelivr.net": ["104.16.85.20", "104.16.86.20"],
    "api.cloudflareclient.com": ["162.159.192.1", "162.159.193.1", "188.114.96.1", "188.114.97.1", "104.16.0.1", "104.17.0.1"]
}

class ForceIPResolver(aiohttp.DefaultResolver):
    def __init__(self, target_ip=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_ip = target_ip

    async def resolve(self, host, port=0, family=0):
        if host in HARDCODED_DNS and self.target_ip:
            return [{"hostname": host, "host": self.target_ip, "port": port, "family": socket.AF_INET, "proto": socket.IPPROTO_TCP, "flags": socket.AI_NUMERICHOST}]
        return await super().resolve(host, port, family)

def get_windows_proxy():
    if platform.system().lower() != 'windows': return None
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings')
        enable, _ = winreg.QueryValueEx(key, 'ProxyEnable')
        if enable:
            server, _ = winreg.QueryValueEx(key, 'ProxyServer')
            if server:
                if '=' in server: server = server.split(';')[0].split('=')[1]
                if not server.startswith('http'): server = f"http://{server}"
                return server
    except: pass
    return None

def atomic_write_json(filepath, data):
    tmp_path = filepath + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f: json.dump(data, f, indent=4)
        os.replace(tmp_path, filepath)
    except Exception as e:
        logger.error(f"Atomic write failed for {filepath}: {e}")

async def generate_warp_keys():
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    priv_key_b64 = base64.b64encode(private_bytes).decode('utf-8')
    public_bytes = private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    pub_key_b64 = base64.b64encode(public_bytes).decode('utf-8')
    return priv_key_b64, pub_key_b64

def calculate_reserved(client_id):
    try:
        if isinstance(client_id, str) and not client_id.isdigit():
            decoded = base64.b64decode(client_id)
            if len(decoded) == 3: return list(decoded)
        cid = int(client_id)
        return [cid >> 16 & 0xFF, cid >> 8 & 0xFF, cid & 0xFF]
    except Exception:
        return [0, 0, 0]

async def auto_register_warp():
    logger.info("Attempting to register new WARP account...")
    priv_key, pub_key = await generate_warp_keys()
    install_id = str(uuid.uuid4())
    fcm_token = f"{install_id}:APA91b" + "".join(random.choices(string.ascii_letters + string.digits, k=134))
    
    payload = {"key": pub_key, "install_id": install_id, "fcm_token": fcm_token, "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()), "model": "PC", "serial_number": install_id[:10], "locale": "en_US", "referrer": "5372edd6-58f6-4f41-b43b-3a4130c2df2a"}
    headers = {"Content-Type": "application/json; charset=UTF-8", "User-Agent": "okhttp/3.12.1", "CF-Client-Version": "a-6.11-2223"}
    ssl_ctx = ssl.create_default_context()

    for ip in HARDCODED_DNS["api.cloudflareclient.com"]:
        try:
            resolver = ForceIPResolver(target_ip=ip)
            connector = aiohttp.TCPConnector(resolver=resolver, ssl=ssl_ctx)
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), connector=connector, trust_env=False) as session:
                async with session.post("https://api.cloudflareclient.com/v0a2223/reg", json=payload, headers=headers) as resp:
                    result = await process_warp_response(resp, priv_key)
                    if result: return result
        except Exception as e:
            logger.warning(f"Failed with IP {ip}: {e}")
            
    logger.error("All Cloudflare IPs failed for WARP registration.")
    return None

async def process_warp_response(resp, priv_key):
    if resp.status == 200:
        data = await resp.json()
        client_id = data.get("config", {}).get("client_id", "0")
        endpoint_ip = data["config"]["peers"][0]["endpoint"]["v4"].split(":")[0]
        warp_data = {"private_key": priv_key, "ipv4_address": data["config"]["interface"]["addresses"]["v4"], "ipv6_address": data["config"]["interface"]["addresses"]["v6"], "peer_public_key": data["config"]["peers"][0]["public_key"], "endpoint": f"{endpoint_ip}:2408", "reserved": calculate_reserved(client_id)}
        logger.info("WARP registered successfully!")
        return warp_data
    else:
        err = await resp.text()
        logger.error(f"WARP registration failed. Status: {resp.status} - {err}")
        return None

def extract_configs_from_text(content):
    valid_protos = ("vless://", "trojan://", "hysteria2://", "hy2://", "vmess://", "ss://")
    links = [line.strip() for line in content.split('\n') if line.strip().startswith(valid_protos)]
    if not links:
        try:
            clean_content = content.replace("\n", "").replace("\r", "").replace("\\", "").strip()
            missing_padding = len(clean_content) % 4
            if missing_padding: clean_content += '=' * (4 - missing_padding)
            decoded_str = base64.b64decode(clean_content).decode('utf-8')
            links = [line.strip() for line in decoded_str.split('\n') if line.strip().startswith(valid_protos)]
        except Exception: pass
    return list(set(links))

def deduplicate_configs(links):
    seen_keys = set()
    unique_links = []
    for link in links:
        creds = parse_config_link(link)
        if creds["protocol"] == "unsupported": continue
        proto = creds["protocol"]
        host = creds.get(f"{proto}_server_ip"); port = creds.get(f"{proto}_port")
        identifier = ""
        if proto == "vless": identifier = creds.get("vless_uuid", "")
        elif proto == "vmess": identifier = creds.get("vmess_uuid", "")
        elif proto == "trojan": identifier = creds.get("trojan_password", "")
        elif proto == "ss": identifier = creds.get("ss_password", "")
        elif proto in ("hysteria2", "hy2"): identifier = creds.get("hysteria_password", "")
        elif proto == "tuic": identifier = creds.get("tuic_uuid", "")
        elif proto == "shadowtls": identifier = creds.get("shadowtls_password", "")
        elif proto in ("naive", "naive+https"): identifier = creds.get("naive_user", "")
        if host and port and identifier:
            dedup_key = f"{proto}:{host}:{port}:{identifier}"
            if dedup_key not in seen_keys: seen_keys.add(dedup_key); unique_links.append(link)
        else: unique_links.append(link)
    return unique_links

latency_sem = asyncio.Semaphore(50)

async def test_tcp_latency(host, port, timeout=1.5):
    start = time.time()
    try:
        async with latency_sem:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            latency = round((time.time() - start) * 1000, 2)
            writer.close(); await writer.wait_closed()
            return latency
    except: return None

async def test_tls_handshake(host, port, sni):
    if not sni: return False
    try:
        ssl_ctx = ssl.create_default_context(); ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
        async with latency_sem:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host=host, port=port, ssl=ssl_ctx, server_hostname=sni), timeout=2.0)
            writer.close(); await writer.wait_closed()
            return True
    except: return False

async def filter_alive_configs(links):
    logger.info(f"Validating and testing {len(links)} unique links...")
    async def check_link(link):
        creds = parse_config_link(link)
        if creds["protocol"] == "unsupported": return (None, 99999)
        proto = creds["protocol"]; host = creds.get(f"{proto}_server_ip"); port = creds.get(f"{proto}_port")
        if not host or not port: return (None, 99999)
        latency = await test_tcp_latency(host, port)
        if latency is None: return (None, 99999)
        if proto in ["vless", "trojan", "shadowtls", "hysteria2", "tuic"]:
            sni_key = f"{proto}_sni" if proto != "trojan" else "trojan_domain"
            sni = creds.get(sni_key, "")
            if sni and not await test_tls_handshake(host, port, sni): return (None, 99999)
        return (link, latency)
    tasks = [check_link(link) for link in links]
    results = await asyncio.gather(*tasks)
    alive_links = [(r, lat) for r, lat in results if r is not None]
    alive_links.sort(key=lambda x: x[1])
    top_links = [link for link, lat in alive_links[:50]]
    logger.info(f"Alive and fast configs: {len(top_links)}/{len(links)}")
    return top_links

def extract_cloudflare_worker(configs):
    workers_found = []
    for link in configs:
        creds = parse_config_link(link)
        if creds["protocol"] == "vless":
            try:
                parsed = urlparse(link); params = parse_qs(parsed.query)
                if params.get("type", [""])[0] == "ws" and params.get("security", [""])[0] == "tls":
                    worker_host = params.get("host", [""])[0] or params.get("sni", [""])[0]
                    worker_id = parsed.username; worker_path = unquote(params.get("path", ["/"])[0])
                    if worker_host and worker_id: workers_found.append({"id": worker_id, "host": worker_host, "path": worker_path})
            except: continue
    if workers_found:
        logger.info(f"Found {len(workers_found)} Cloudflare Worker configs.")
        return workers_found[0]
    return None

async def fetch_from_url(url, proxy_url=None):
    proxy = get_windows_proxy()
    timeout = aiohttp.ClientTimeout(total=15)
    headers = {"User-Agent": "Mozilla/5.0"}
    
    if proxy:
        try:
            async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
                async with session.get(url, headers=headers, proxy=proxy) as resp:
                    if resp.status == 200: return await resp.text()
        except Exception as e:
            logger.debug(f"Fetch via proxy failed for {url}: {e}")

    if "raw.githubusercontent.com" in url:
        try:
            ssl_ctx = ssl.create_default_context()
            target_ip = random.choice(HARDCODED_DNS["raw.githubusercontent.com"])
            resolver = ForceIPResolver(target_ip=target_ip)
            connector = aiohttp.TCPConnector(resolver=resolver, ssl=ssl_ctx)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector, trust_env=False) as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200: return await resp.text()
        except Exception as e:
            logger.debug(f"Direct GitHub fetch failed for {url}: {e}")

        jsdelivr_url = url.replace("https://raw.githubusercontent.com/", "https://cdn.jsdelivr.net/gh/").replace("/main/", "@main/").replace("/master/", "@master/")
        try:
            async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
                async with session.get(jsdelivr_url, headers=headers) as resp:
                    if resp.status == 200: return await resp.text()
        except Exception as e:
            logger.debug(f"jsDelivr fetch failed for {url}: {e}")

        try:
            ssl_ctx = ssl.create_default_context()
            target_ip = random.choice(HARDCODED_DNS["cdn.jsdelivr.net"])
            resolver = ForceIPResolver(target_ip=target_ip)
            connector = aiohttp.TCPConnector(resolver=resolver, ssl=ssl_ctx)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector, trust_env=False) as session:
                async with session.get(jsdelivr_url, headers=headers) as resp:
                    if resp.status == 200: return await resp.text()
        except Exception as e:
            logger.debug(f"jsDelivr (hardcoded IP) fetch failed for {url}: {e}")

        try:
            githack_url = url.replace("https://raw.githubusercontent.com/", "https://raw.githack.com/")
            async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
                async with session.get(githack_url, headers=headers) as resp:
                    if resp.status == 200: return await resp.text()
        except Exception as e:
            logger.debug(f"githack fetch failed for {url}: {e}")
            
    else:
        try:
            async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200: return await resp.text()
        except Exception as e:
            logger.debug(f"Direct fetch failed for {url}: {e}")

    if proxy_url:
        try:
            from aiohttp_socks import ProxyConnector
            connector = ProxyConnector.from_url(proxy_url)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector, trust_env=False) as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200: return await resp.text()
        except Exception as e:
            logger.debug(f"Bootstrap-proxy fetch failed for {url}: {e}")

    logger.warning(f"Failed to fetch from {url}")
    return None

async def fetch_public_configs(bootstrap_proxy=None):
    logger.info("Fetching public configs...")
    all_links = []
    tasks = [fetch_from_url(url, proxy_url=bootstrap_proxy) for url in FREE_CONFIGS_URLS]
    results = await asyncio.gather(*tasks)
    for content in results:
        if content: all_links.extend(extract_configs_from_text(content))
    unique_links = deduplicate_configs(list(set(all_links)))
    alive_links = await filter_alive_configs(unique_links)
    return alive_links

async def main(override_urls=None, bootstrap_proxy: str = None):
    output_data = {"configs": [], "subscription_urls": [], "warp": None, "cloudflare_worker": None, "psiphon": None, "dnstt": None}

    if bootstrap_proxy:
        logger.info(f"Bootstrap proxy active for this fetch cycle: {bootstrap_proxy}")

    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
                if "warp" in existing_data and existing_data["warp"]: output_data["warp"] = existing_data["warp"]
                if "cloudflare_worker" in existing_data and existing_data["cloudflare_worker"]: output_data["cloudflare_worker"] = existing_data["cloudflare_worker"]
                if "subscription_urls" in existing_data and existing_data["subscription_urls"]: output_data["subscription_urls"] = existing_data["subscription_urls"]
        except Exception as e: logger.warning(f"Could not read existing file: {e}")

    user_subs = override_urls if override_urls is not None else output_data.get("subscription_urls", [])
    output_data["subscription_urls"] = user_subs
    all_links = []

    if user_subs:
        logger.info("Fetching user custom subscriptions...")
        tasks = [fetch_from_url(url, proxy_url=bootstrap_proxy) for url in user_subs]
        results = await asyncio.gather(*tasks)
        for content in results:
            if content: all_links.extend(extract_configs_from_text(content))
        
        if all_links:
            output_data["configs"] = deduplicate_configs(list(set(all_links)))
            atomic_write_json(OUTPUT_FILE, output_data)
            logger.info("User subs saved temporarily. Fetching public configs...")

    public_links = await fetch_public_configs(bootstrap_proxy=bootstrap_proxy)
    all_links.extend(public_links)
    
    if all_links: 
        unique_combined = deduplicate_configs(list(set(all_links)))
        alive_links = await filter_alive_configs(unique_combined)
        if alive_links:
            output_data["configs"] = alive_links
            if not output_data["cloudflare_worker"]:
                worker = extract_cloudflare_worker(alive_links)
                if worker: output_data["cloudflare_worker"] = worker

    if not output_data["warp"]:
        warp_keys = await auto_register_warp()
        if warp_keys: output_data["warp"] = warp_keys

    atomic_write_json(OUTPUT_FILE, output_data)
    logger.info("Data saved successfully.")
    logger.info(f"Fetch cycle finished: {len(output_data['configs'])} usable configs saved.")

if __name__ == "__main__":
    asyncio.run(main())
    sys.exit(0)