import os
from strategies.base import Strategy
from core.utils import atomic_write_json
import logging

logger = logging.getLogger("NetAnalyzer")


class TuicStrategy(Strategy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary_name = "tuic"

    async def prepare(self) -> tuple:

        creds = self.creds

        config = {
            "server": f"{creds['tuic_server_ip']}:{creds['tuic_port']}",
            "uuid": creds["tuic_uuid"],
            "password": creds["tuic_password"],
            "tls": {
                "sni": creds["tuic_sni"],
                "alpn": [creds["tuic_alpn"]],
                "insecure": creds["tuic_insecure"],
            },
            "socks5": {"listen": f"127.0.0.1:{self.local_socks_port}"},
            "http": {"listen": f"127.0.0.1:{self.local_http_port}"},
            "udp_relay_mode": "native",
            "congestion_control": "bbr",
        }

        config_file = "auto_bypass_config_tuic.json"
        atomic_write_json(os.path.join(self.data_dir, config_file), config)

        self._config_file = config_file

        return config_file, "tuic"
