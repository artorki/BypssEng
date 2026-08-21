


import os
from strategies.base import Strategy
from core.utils import atomic_write_json
from typing import List
import logging

logger = logging.getLogger("NetAnalyzer")

class DnsttStrategy(Strategy):
    """
    DNSTT Runtime Model (HANDOFF Sec 15):
    Converted from single-executable to multi-process architecture.
    Requires both dnstt-client (to establish DNS tunnel) and xray (to route traffic).
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary_name = "xray"  # Main inbound listener
        

        self.local_dntt_port: int = None
        self.dnstt_domain: str = None
        self.dnstt_pubkey: str = None

    async def prepare(self) -> tuple:
        """Prepares Xray config to route traffic to the local dnstt-client port."""
        creds = self.creds
        self.dnstt_domain = creds.get("dnstt_domain")
        self.dnstt_pubkey = creds.get("dnstt_pubkey")
        
        if not self.dnstt_domain or not self.dnstt_pubkey:
            logger.error("DNSTT: Missing domain or pubkey in credentials.")
            return None, None
            


        self.local_dntt_port = self.local_socks_port + 1000
        

        config = {
            "log": {"loglevel": "warning"}, 
            "dns": {"servers": ["https+local://8.8.8.8/dns-query", "localhost"], "queryStrategy": "UseIP"}, 
            "inbounds": [
                {"port": self.local_socks_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}}, 
                {"port": self.local_http_port, "listen": "127.0.0.1", "protocol": "http", "settings": {}}
            ],
            "outbounds": [
                {"tag": "proxy", "protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": self.local_dntt_port}]}}, 
                {"tag": "dns-out", "protocol": "dns"}, 
                {"tag": "direct", "protocol": "freedom"}
            ]
        }
        
        config_file = "auto_bypass_config_dnstt.json"
        atomic_write_json(os.path.join(self.data_dir, config_file), config)
        

        self._config_file = config_file
        return config_file, "xray"

    def dependencies(self) -> List[str]:
        """Section 15: DNSTT requires both Xray and dnstt-client"""
        return ["xray", "dnstt-client"]

    def processes(self) -> List[List[str]]:
        """
        Section 15: Returns list of processes to start.
        1. dnstt-client (establishes DNS tunnel on local_dntt_port)
        2. xray (listens on user ports and routes to dnstt-client)
        """
        if not self._config_file or not self.local_dntt_port:
            return []
            
        dnstt_binary = self.binary_paths.get("dnstt-client")
        xray_binary = self.binary_paths.get("xray")
        
        if not dnstt_binary or not xray_binary:
            logger.error("DNSTT: Missing required binaries.")
            return []
            
        abs_config_file = os.path.join(self.data_dir, self._config_file)
        

        dnstt_cmd = [
            dnstt_binary,
            '-u', f"{self.dnstt_pubkey}@{self.dnstt_domain}",
            '-local', f"127.0.0.1:{self.local_dntt_port}"
        ]
        

        xray_cmd = self.get_command_args(xray_binary, abs_config_file)
        

        return [dnstt_cmd, xray_cmd]
        
    async def cleanup(self):
        """Section 15: Ensure auxiliary ports/state are cleared"""
        self.local_dntt_port = None
        self.dnstt_domain = None
        self.dnstt_pubkey = None