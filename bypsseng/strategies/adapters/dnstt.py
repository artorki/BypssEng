import os
from strategies.base import Strategy
from core.utils import atomic_write_json

class DnsttStrategy(Strategy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary_name = "xray+dnstt"

    async def prepare(self):
        creds = self.creds
        dnstt_domain = creds.get("dnstt_domain"); dnstt_pubkey = creds.get("dnstt_pubkey")
        if not dnstt_domain or not dnstt_pubkey: return None, None
        
        local_dntt_port = self.local_socks_port + 1000
        creds["dnstt_local_port"] = local_dntt_port
        
        config = {
            "log": {"loglevel": "warning"}, "dns": {"servers": ["https+local://8.8.8.8/dns-query", "localhost"], "queryStrategy": "UseIP"}, 
            "inbounds": [{"port": self.local_socks_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}}, {"port": self.local_http_port, "listen": "127.0.0.1", "protocol": "http", "settings": {}}],
            "outbounds": [{"tag": "proxy", "protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": local_dntt_port}]}}, {"tag": "dns-out", "protocol": "dns"}, {"tag": "direct", "protocol": "freedom"}]
        }
        atomic_write_json(os.path.join(self.data_dir, "auto_bypass_config_dnstt.json"), config)
        return "auto_bypass_config_dnstt.json", "xray+dnstt"
