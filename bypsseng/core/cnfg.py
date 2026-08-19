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
import re
from urllib.parse import urlparse, parse_qs, unquote

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Error: 'cryptography' is not installed. Please run: pip install cryptography")
    sys.exit(1)

logging.basicConfig(filename='cnfg.log', level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("Fetcher")

FREE_CONFIGS_URLS = [
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/vless",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/trojan",
    
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/mixed",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/vless",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/trojan",
    
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/AzadNetCh/NetV2/main/qsub"
]

OUTPUT_FILE = "cnfg.json"
LOCAL_PROXY = "http://127.0.0.1:10809"

HARDCODED_DNS = {
    "raw.githubusercontent.com": ["185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133"],
    "api.cloudflareclient.com": ["162.159.192.1", "162.159.193.1", "188.114.96.1", "188.114.97.1", "104.16.0.1", "104.17.0.1"]
}

class ForceIPResolver(aiohttp.DefaultResolver):
    def __init__(self, target_ip=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_ip = target_ip

    async def resolve(self, host, port=0, family=0):
        if host in HARDCODED_DNS and self.target_ip:
            ip = self.target_ip
            logger.info(f"Direct mode: Forcing IP {ip} for {host} while keeping SNI intact.")
            return [{
                "hostname": host, 
                "host": ip, 
                "port": port, 
                "family": socket.AF_INET, 
                "proto": socket.IPPROTO_TCP, 
                "flags": socket.AI_NUMERICHOST
            }]
        return await super().resolve(host, port, family)

def atomic_write_json(filepath, data):
    tmp_path = filepath + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        os.replace(tmp_path, filepath)
    except Exception as e:
        logger.error(f"Atomic write failed for {filepath}: {e}")

async def check_local_proxy():
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", 10809), timeout=2)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

async def generate_warp_keys():
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw, 
        format=serialization.PrivateFormat.Raw, 
        encryption_algorithm=serialization.NoEncryption()
    )
    priv_key_b64 = base64.b64encode(private_bytes).decode('utf-8')
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, 
        format=serialization.PublicFormat.Raw
    )
    pub_key_b64 = base64.b64encode(public_bytes).decode('utf-8')
    return priv_key_b64, pub_key_b64

def calculate_reserved(client_id):
    try:
        if isinstance(client_id, str) and not client_id.isdigit():
            decoded = base64.b64decode(client_id)
            if len(decoded) == 3:
                return list(decoded)
        cid = int(client_id)
        return [cid >> 16 & 0xFF, cid >> 8 & 0xFF, cid & 0xFF]
    except Exception:
        return [0, 0, 0]

async def auto_register_warp(use_proxy):
    logger.info(f"Attempting to register new WARP account (Proxy: {use_proxy})...")
    
    priv_key, pub_key = await generate_warp_keys()
    install_id = str(uuid.uuid4())
    fcm_token = f"{install_id}:APA91b" + "".join(random.choices(string.ascii_letters + string.digits, k=134))
    referrer = "5372edd6-58f6-4f41-b43b-3a4130c2df2a" 
    
    payload = {
        "key": pub_key, "install_id": install_id, "fcm_token": fcm_token, 
        "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()), 
        "model": "PC", "serial_number": install_id[:10], "locale": "en_US",
        "referrer": referrer
    }
    headers = {
        "Content-Type": "application/json; charset=UTF-8", 
        "User-Agent": "okhttp/3.12.1", 
        "CF-Client-Version": "a-6.11-2223"
    }
    
    ssl_ctx = ssl.create_default_context()

    if use_proxy:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
                url = "https://api.cloudflareclient.com/v0a2223/reg"
                async with session.post(url, json=payload, headers=headers, proxy=LOCAL_PROXY) as resp:
                    return await process_warp_response(resp, priv_key)
        except Exception as e:
            logger.error(f"WARP registration exception via proxy: {e}")
            return None
    else:
        for ip in HARDCODED_DNS["api.cloudflareclient.com"]:
            logger.info(f"Trying Cloudflare IP: {ip}")
            try:
                resolver = ForceIPResolver(target_ip=ip)
                connector = aiohttp.TCPConnector(resolver=resolver, ssl=ssl_ctx)
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), connector=connector) as session:
                    url = "https://api.cloudflareclient.com/v0a2223/reg"
                    async with session.post(url, json=payload, headers=headers) as resp:
                        result = await process_warp_response(resp, priv_key)
                        if result:
                            return result
            except Exception as e:
                logger.warning(f"Failed with IP {ip}: {e}")
                
        logger.error("All Cloudflare IPs failed for WARP registration.")
        return None

async def process_warp_response(resp, priv_key):
    if resp.status == 200:
        data = await resp.json()
        
        client_id = data.get("config", {}).get("client_id")
        if not client_id:
            client_id = data.get("config", {}).get("peers", [{}])[0].get("client_id", "0")
            
        endpoint_v4 = data["config"]["peers"][0]["endpoint"]["v4"]
        endpoint_ip = endpoint_v4.split(":")[0]
        fixed_endpoint = f"{endpoint_ip}:2408"
        
        warp_data = {
            "private_key": priv_key,
            "ipv4_address": data["config"]["interface"]["addresses"]["v4"],
            "ipv6_address": data["config"]["interface"]["addresses"]["v6"],
            "peer_public_key": data["config"]["peers"][0]["public_key"],
            "endpoint": fixed_endpoint,
            "reserved": calculate_reserved(client_id)
        }
        logger.info(f"WARP registered successfully! Client ID: {client_id}, Endpoint: {fixed_endpoint}")
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
            if missing_padding:
                clean_content += '=' * (4 - missing_padding)
                
            decoded_bytes = base64.b64decode(clean_content)
            decoded_str = decoded_bytes.decode('utf-8')
            links = [line.strip() for line in decoded_str.split('\n') if line.strip().startswith(valid_protos)]
        except Exception:
            pass
            
    return list(set(links))

def extract_host_port(link):
    try:
        if link.startswith("vmess://"):
            raw_b64 = link[8:]
            missing_padding = len(raw_b64) % 4
            if missing_padding: raw_b64 += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(raw_b64).decode('utf-8'))
            return data.get("add"), int(data.get("port", 443))
        else:
            parsed = urlparse(link)
            return parsed.hostname, parsed.port
    except:
        return None, None

def deduplicate_configs(links):
    unique_servers = {}
    clean_links = []
    
    for link in links:
        host, port = extract_host_port(link)
        if host and port:
            server_key = f"{host}:{port}"
            if server_key not in unique_servers:
                unique_servers[server_key] = True
                clean_links.append(link)
        else:
            clean_links.append(link)
            
    return clean_links

latency_sem = asyncio.Semaphore(50) 

async def test_tcp_latency(host, port, timeout=1.5):

    start = time.time()
    try:
        async with latency_sem:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            latency = round((time.time() - start) * 1000, 2)
            writer.close()
            await writer.wait_closed()
            return latency
    except:
        return None

async def test_tls_handshake(host, port, sni):

    if not sni:
        return False
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        async with latency_sem:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port, ssl=ssl_ctx, server_hostname=sni), 
                timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            return True
    except:
        return False

async def filter_alive_configs(links, use_proxy):
    logger.info(f"Testing TCP latency and TLS Handshake for {len(links)} configs...")
    
    async def check_link(link):
        host, port = extract_host_port(link)
        if not host or not port:
            return (None, 99999)
        
        latency = await test_tcp_latency(host, port)
        if latency is None:
            return (None, 99999)
    
        if "sni=" in link or "tls" in link or "reality" in link:
            sni_match = re.search(r'sni=([^&]+)', link) or re.search(r'host=([^&]+)', link)
            if sni_match:
                sni = sni_match.group(1)
            
                if not await test_tls_handshake(host, port, sni):
                    return (None, 99999)
        
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
        if link.startswith("vless://"):
            try:
                parsed = urlparse(link)
                params = parse_qs(parsed.query)
                if params.get("type", [""])[0] == "ws" and params.get("security", [""])[0] == "tls":
                    worker_host = params.get("host", [""])[0] or params.get("sni", [""])[0]
                    worker_id = parsed.username
                    worker_path = unquote(params.get("path", ["/"])[0])
                    if worker_host and worker_id:
                        workers_found.append({"id": worker_id, "host": worker_host, "path": worker_path})
            except Exception:
                continue
                
    if workers_found:
        logger.info(f"Found {len(workers_found)} Cloudflare Worker configs. Selecting the first one.")
        return workers_found[0]
    return None

async def fetch_from_url(url, use_proxy):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        ssl_ctx = ssl.create_default_context()
        timeout = aiohttp.ClientTimeout(total=15)
        
        if use_proxy:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers, proxy=LOCAL_PROXY) as resp:
                    if resp.status == 200:
                        return await resp.text()
        else:
            target_ip = random.choice(HARDCODED_DNS["raw.githubusercontent.com"])
            resolver = ForceIPResolver(target_ip=target_ip)
            connector = aiohttp.TCPConnector(resolver=resolver, ssl=ssl_ctx)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        return await resp.text()
    except Exception as e:
        logger.warning(f"Failed to fetch from {url}: {e}")
    return None

async def fetch_public_configs(use_proxy):
    logger.info(f"Fetching public configs from multiple sources (Proxy: {use_proxy})...")
    all_links = []
    
    tasks = [fetch_from_url(url, use_proxy) for url in FREE_CONFIGS_URLS]
    results = await asyncio.gather(*tasks)
    
    for content in results:
        if content:
            links = extract_configs_from_text(content)
            all_links.extend(links)
            
    unique_links = list(set(all_links))
    logger.info(f"Fetched total {len(unique_links)} unique raw links.")
    
    deduped_links = deduplicate_configs(unique_links)
    logger.info(f"Deduplicated to {len(deduped_links)} unique servers.")
    
    alive_links = await filter_alive_configs(deduped_links, use_proxy)
    
    return alive_links

async def main():
    output_data = {"configs": [], "subscription_urls": [], "warp": None, "cloudflare_worker": None, "psiphon": None, "dnstt": None}

    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
                if "warp" in existing_data and existing_data["warp"]:
                    output_data["warp"] = existing_data["warp"]
                if "cloudflare_worker" in existing_data and existing_data["cloudflare_worker"]:
                    output_data["cloudflare_worker"] = existing_data["cloudflare_worker"]
        
                if "subscription_urls" in existing_data and existing_data["subscription_urls"]:
                    output_data["subscription_urls"] = existing_data["subscription_urls"]
        except json.JSONDecodeError:
            logger.warning("Existing JSON is corrupted, starting fresh.")
        except Exception as e:
            logger.warning(f"Could not read existing file: {e}")

    use_proxy = await check_local_proxy()
    all_links = []


    user_subs = output_data.get("subscription_urls", [])
    if user_subs:
        logger.info(f"Fetching {len(user_subs)} user custom subscriptions...")
        tasks = [fetch_from_url(url, use_proxy) for url in user_subs]
        results = await asyncio.gather(*tasks)
        for content in results:
            if content:
                all_links.extend(extract_configs_from_text(content))


    public_links = await fetch_public_configs(use_proxy)
    all_links.extend(public_links)
    
    if all_links: 
    
        unique_links = list(set(all_links))
        logger.info(f"Total unique raw links gathered: {len(unique_links)}")
        
    
        alive_links = await filter_alive_configs(unique_links, use_proxy)
        
        if alive_links:
            output_data["configs"] = alive_links
            if not output_data["cloudflare_worker"]:
                worker = extract_cloudflare_worker(alive_links)
                if worker:
                    output_data["cloudflare_worker"] = worker

    if not output_data["warp"]:
        warp_keys = await auto_register_warp(use_proxy)
        if warp_keys: 
            output_data["warp"] = warp_keys

    atomic_write_json(OUTPUT_FILE, output_data)
    logger.info(f"Data saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
    sys.exit(0)
