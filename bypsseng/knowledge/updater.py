


import os
import json
import shutil
import aiohttp
import hashlib
import logging
from typing import Optional, Dict

logger = logging.getLogger("NetAnalyzer")

class KnowledgeUpdater:
    """
    Section 32 & 59: Secure Knowledge Update Model.
    Downloads, verifies, and updates compatibility data safely.
    """
    def __init__(self, knowledge_file: str, remote_url: str, expected_hash: Optional[str] = None):
        self.knowledge_file = knowledge_file
        self.remote_url = remote_url
        self.expected_hash = expected_hash
        self.backup_file = knowledge_file + ".bak"

    def _verify_hash(self, file_path: str, expected_hash: str) -> bool:
        """Verifies SHA256 hash of the downloaded file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        actual_hash = sha256_hash.hexdigest()
        return actual_hash == expected_hash

    def _validate_schema(self, data: Dict) -> bool:
        """Validates the basic schema of the compatibility JSON."""
        if "version" not in data or "strategies" not in data:
            return False
        return True

    async def check_and_update(self):
        """Downloads, verifies, and applies the knowledge update."""
        logger.info("Checking for Knowledge Base updates...")
        
        tmp_path = self.knowledge_file + ".tmp"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.remote_url) as resp:
                    if resp.status == 200:
                        with open(tmp_path, 'wb') as f:
                            async for chunk in resp.content.iter_chunked(8192):
                                f.write(chunk)
                    else:
                        logger.error(f"Failed to download knowledge update. HTTP Status: {resp.status}")
                        return False


            if self.expected_hash and not self._verify_hash(tmp_path, self.expected_hash):
                logger.error("Knowledge update hash verification failed! Aborting update.")
                os.remove(tmp_path)
                return False


            with open(tmp_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not self._validate_schema(data):
                logger.error("Knowledge update schema validation failed! Aborting update.")
                os.remove(tmp_path)
                return False


            if os.path.exists(self.knowledge_file):
                shutil.copy2(self.knowledge_file, self.backup_file)
                logger.info("Backed up current knowledge base for rollback.")


            os.replace(tmp_path, self.knowledge_file)
            logger.info(f"Knowledge Base successfully updated to version {data.get('version')}.")
            return True

        except Exception as e:
            logger.error(f"Knowledge update failed: {e}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            return False

    def rollback(self):
        """Rolls back to the previous knowledge base version."""
        if os.path.exists(self.backup_file):
            shutil.copy2(self.backup_file, self.knowledge_file)
            os.remove(self.backup_file)
            logger.info("Knowledge Base rolled back to previous version.")
            return True
        logger.warning("No backup file found for rollback.")
        return False