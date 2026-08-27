import os
from strategies.base import Strategy
from core.utils import atomic_write_json
import logging

logger = logging.getLogger("NetAnalyzer")


class PsiphonStrategy(Strategy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary_name = "psiphon"

    async def prepare(self) -> tuple:

        config = {
            "PropagationChannelId": "FFFFFFFFFFFFFFFF",
            "RemoteServerListURLs": [
                {
                    "URLFormat": "https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed",
                    "SignaturePublicKey": "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvZ9NcPAwW0/J4T0F4xjVqr1Xy2bUHDDQC4iRpvLjoyb/IE1kgroBtQR1Ptg2QzTiEDuZqOHSQjvy37LhOFd0n7d4QOWfX3MGts9CpfA9IyRE0LeGe4O3Dz1m1ZI76t1tWc5q9qY+vYrn6Qp8dWwL6r56Y3pucyD1W1qYwdc8gq5sQm2b9O7BZ9Sa1r1l1e2vKH/1t5xQf1t3t3f1Qv1t1wR1t1sP1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1t1=",
                }
            ],
            "LocalSocksProxyPort": self.local_socks_port,
            "LocalHttpProxyPort": self.local_http_port,
            "DisableLocalSocksProxy": False,
        }

        config_file = "psiphon_config.json"
        atomic_write_json(os.path.join(self.data_dir, config_file), config)

        self._config_file = config_file

        return config_file, "psiphon"
