import os
from strategies.base import Strategy
from core.utils import atomic_write_json

class SingboxStrategy(Strategy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary_name = "singbox"

    async def prepare(self):
        creds = self.creds
        config = {
            "log": {"level": "warn"},
            "inbounds": [
                {"type": "http", "listen": "127.0.0.1", "listen_port": self.local_http_port},
                {"type": "socks", "listen": "127.0.0.1", "listen_port": self.local_socks_port}
            ],
            "outbounds": []
        }
        
        if creds["protocol"] in ("hysteria2", "hy2"):
            config["outbounds"].append({
                "type": "hysteria2",
                "server": creds["hysteria_server_ip"],
                "server_port": creds["hysteria_port"],
                "password": creds["hysteria_password"],
                "tls": {"server_name": creds["hysteria_sni"], "insecure": creds["hysteria_insecure"]}
            })
        elif creds["protocol"] == "tuic":
            config["outbounds"].append({
                "type": "tuic",
                "server": creds["tuic_server_ip"],
                "server_port": creds["tuic_port"],
                "uuid": creds["tuic_uuid"],
                "password": creds["tuic_password"],
                "tls": {"server_name": creds["tuic_sni"], "alpn": [creds["tuic_alpn"]], "insecure": creds["tuic_insecure"]}
            })
            
        atomic_write_json(os.path.join(self.data_dir, "auto_bypass_config_singbox.json"), config)
        return "auto_bypass_config_singbox.json", "singbox"