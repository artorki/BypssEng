import os
from strategies.base import Strategy
from core.utils import atomic_write_json
import logging

logger = logging.getLogger("NetAnalyzer")


class NaiveStrategy(Strategy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary_name = "naive"

    async def prepare(self) -> tuple:

        creds = self.creds

        config = {
            "listen": f"http://127.0.0.1:{self.local_http_port}",
            "proxy": f"https://{creds['naive_user']}:{creds['naive_password']}@{creds['naive_server_ip']}:{creds['naive_port']}",
        }

        if creds.get("naive_sni"):
            config["host-resolver-rules"] = f"SN,{creds['naive_sni']}"

        config_file = "auto_bypass_config_naive.json"
        atomic_write_json(os.path.join(self.data_dir, config_file), config)

        self._config_file = config_file

        return config_file, "naive"
