import os
from strategies.base import Strategy
from core.utils import atomic_write_json
import logging

logger = logging.getLogger("NetAnalyzer")


class HysteriaStrategy(Strategy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary_name = "hysteria"

    async def prepare(self) -> tuple:

        creds = self.creds

        config = {
            "server": f"{creds['hysteria_server_ip']}:{creds['hysteria_port']}",
            "auth": creds["hysteria_password"],
            "tls": {
                "sni": creds["hysteria_sni"],
                "insecure": creds["hysteria_insecure"],
            },
            "socks5": {"listen": f"127.0.0.1:{self.local_socks_port}"},
            "http": {"listen": f"127.0.0.1:{self.local_http_port}"},
            "up": "100 Mbps",
            "down": "100 Mbps",
        }

        if creds.get("hysteria_obfs"):
            config["obfs"] = {"type": creds["hysteria_obfs"]}
            if creds["hysteria_obfs"] == "salamander":
                config["obfs"]["salamander"] = {
                    "password": creds["hysteria_obfs_password"]
                }

        config_file = "auto_bypass_config_hy2.json"
        atomic_write_json(os.path.join(self.data_dir, config_file), config)

        self._config_file = config_file

        return config_file, "hysteria"
