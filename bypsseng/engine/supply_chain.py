


import os
import json
import hashlib
import aiohttp
import logging
from core.logger import log

logger = logging.getLogger("NetAnalyzer")

class SupplyChainManager:
    """
    Secure Asset Verification (HANDOFF Sec 22, 64):
    All external binaries and data files must be verified against manifest.json
    using SHA256 hashes before being accepted as trusted.
    """
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.third_party_dir = os.path.join(base_dir, "third_party")
        self.data_dir = os.path.join(base_dir, "Data")
        self.manifest_path = os.path.join(self.third_party_dir, "manifest.json")
        
        os.makedirs(self.third_party_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)
        
        self.manifest = self._load_manifest()

    def _load_manifest(self) -> dict:
        """Loads the manifest.json file securely."""
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.error("Supply Chain: manifest.json is corrupted.")
                return {"assets": []}
        return {"assets": []}

    async def verify_hash(self, file_path: str, expected_hash: str) -> bool:
        """Verify SHA256 hash of a file (HANDOFF Sec 22)."""
        if not os.path.exists(file_path): 
            return False
            
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""): 
                sha256_hash.update(chunk)
        actual_hash = sha256_hash.hexdigest()
        
        if actual_hash == expected_hash:
            log(f"Supply Chain: Hash verified for {os.path.basename(file_path)}", "PASS")
            return True
        
        log(f"Supply Chain: Hash mismatch for {os.path.basename(file_path)}! Expected: {expected_hash[:10]}..., Got: {actual_hash[:10]}...", "ERROR")
        return False

    async def download_asset(self, asset_name: str) -> bool:
        """Download and verify an asset securely based on manifest metadata (HANDOFF Sec 22)."""
        asset_info = next((a for a in self.manifest.get("assets", []) if a.get("name") == asset_name), None)
        if not asset_info:
            logger.error(f"Supply Chain: Asset '{asset_name}' not found in manifest.")
            return False

        url = asset_info.get("source_url")
        expected_hash = asset_info.get("sha256")
        target_dir = asset_info.get("target_dir", "Data")
        filename = asset_info.get("filename", asset_name)
        target_path = os.path.join(self.base_dir, target_dir, filename)
        
        if not url or not expected_hash:
            logger.error(f"Supply Chain: Missing URL or Hash for '{asset_name}' in manifest.")
            return False


        if os.path.exists(target_path) and await self.verify_hash(target_path, expected_hash):
            return True

        log(f"Supply Chain: Downloading '{asset_name}' from {url}", "INFO")
        tmp_path = target_path + ".tmp"
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        with open(tmp_path, 'wb') as f:
                            async for chunk in resp.content.iter_chunked(8192):
                                f.write(chunk)
                    else:
                        logger.error(f"Supply Chain: Failed to download '{asset_name}'. HTTP Status: {resp.status}")
                        return False
            

            if await self.verify_hash(tmp_path, expected_hash):
                os.replace(tmp_path, target_path)
                log(f"Supply Chain: '{asset_name}' downloaded and verified successfully.", "PASS")
                return True
            else:

                if os.path.exists(tmp_path): os.remove(tmp_path)
                logger.error(f"Supply Chain: Deleted untrusted file '{asset_name}' due to hash mismatch.")
                return False
                
        except Exception as e:
            logger.error(f"Supply Chain: Download exception for '{asset_name}': {e}")
            if os.path.exists(tmp_path): os.remove(tmp_path)
            return False

    async def ensure_geo_files(self):
        """Download GeoIP and GeoSite files securely."""
        await self.download_asset("geoip")
        await self.download_asset("geosite")