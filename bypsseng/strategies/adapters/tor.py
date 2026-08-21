import os
from strategies.base import Strategy
import logging

logger = logging.getLogger("NetAnalyzer")


class TorStrategy(Strategy):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary_name = "tor"

    async def prepare(self) -> tuple:

        creds = self.creds
        tor_data_dir = os.path.join(self.data_dir, "tor_data").replace("\\", "/")

        if creds["protocol"] == "tor_snowflake":
            snowflake_path = self.binary_paths.get("snowflake")
            lyrebird_path = self.binary_paths.get("lyrebird")

            if snowflake_path and os.path.isfile(snowflake_path):

                torrc_content = (
                    f"DataDirectory {tor_data_dir}\n"
                    f"SocksPort 127.0.0.1:{self.local_socks_port}\n"
                    f"HTTPTunnelPort 127.0.0.1:{self.local_http_port}\n"
                    f"UseBridges 1\n"
                    f"ClientTransportPlugin snowflake exec {snowflake_path}\n"
                    f"Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.org,ajax.aspnetcdn.com ice=stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn\n"
                    f"Bridge snowflake 192.0.2.4:80 8838024498816A039B6BFF4908B6020058B11D18 fingerprint=8838024498816A039B6BFF4908B6020058B11D18 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.org,ajax.aspnetcdn.com ice=stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn\n"
                )
                config_name = "torrc_snowflake"
            elif lyrebird_path and os.path.isfile(lyrebird_path):

                torrc_content = (
                    f"DataDirectory {tor_data_dir}\n"
                    f"SocksPort 127.0.0.1:{self.local_socks_port}\n"
                    f"HTTPTunnelPort 127.0.0.1:{self.local_http_port}\n"
                    f"UseBridges 1\n"
                    f"ClientTransportPlugin obfs4 exec {lyrebird_path}\n"
                    f"Bridge obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1\n"
                    f"Bridge obfs4 38.229.1.78:80 C8CBDB2464FC9804A69531437BCF2BE31FDD2EE4 cert=AA1+Qiae9pr5f17V01d3XvqP5yzP3Y5Dqdpf17TrHpWhVZ0ggpfpXQAU5ADQ iat-mode=1\n"
                )
                config_name = "torrc_obfs4"
            else:
                logger.error("Tor: Missing snowflake and lyrebird binaries.")
                return None, None
        else:

            torrc_content = (
                f"DataDirectory {tor_data_dir}\n"
                f"SocksPort 127.0.0.1:{self.local_socks_port}\n"
                f"HTTPTunnelPort 127.0.0.1:{self.local_http_port}\n"
            )
            config_name = "torrc_proxy"

        config_file = f"{config_name}"
        with open(os.path.join(self.data_dir, config_file), "w") as f:
            f.write(torrc_content)

        self._config_file = config_file

        return config_file, "tor"
