# engine/supply_chain.py
import os
import json
import hashlib
import aiohttp
from core.logger import log

class SupplyChainManager:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.third_party_dir = os.path.join(base_dir, "third_party")
        self.data_dir = os.path.join(base_dir, "Data")
        os.makedirs(self.third_party_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)

    async def ensure_geo_files(self):
        geoip_path = os.path.join(self.data_dir, "geoip.dat")
        geosite_path = os.path.join(self.data_dir, "geosite.dat")
        needs_download = False
        if not os.path.exists(geoip_path) or os.path.getsize(geoip_path) < 1000000: needs_download = True
        if not os.path.exists(geosite_path) or os.path.getsize(geosite_path) < 1000000: needs_download = True

        if needs_download:
            log("Downloading/Updating GeoIP and GeoSite files via SupplyChain...", "SOL")
            urls = {
                geoip_path: ["https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"],
                geosite_path: ["https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"]
            }
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as session:
                for path, url_list in urls.items():
                    for url in url_list:
                        try:
                            async with session.get(url) as resp:
                                if resp.status == 200:
                                    data = await resp.read()
                                    if len(data) > 1000000:
                                        with open(path + ".tmp", 'wb') as f: f.write(data)
                                        os.replace(path + ".tmp", path)
                                        log(f"  -> Saved {os.path.basename(path)}", "PASS")
                                        break
                        except Exception as e:
                            log(f"Failed to download {os.path.basename(path)}: {e}", "WARN")

    async def verify_hash(self, file_path, expected_hash):
        if not os.path.exists(file_path): return False
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""): sha256_hash.update(chunk)
        return sha256_hash.hexdigest() == expected_hash