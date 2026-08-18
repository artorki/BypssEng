import os
from strategies.base import Strategy
from core.logger import log

class TorStrategy(Strategy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary_name = "tor"

    async def prepare(self):
        creds = self.creds
        tor_data_dir = os.path.join(self.data_dir, "tor_data").replace("\\", "/")
        
        if creds["protocol"] == "tor_snowflake":
            snowflake_path = self.binary_paths.get("snowflake")
            lyrebird_path = self.binary_paths.get("lyrebird")
            if snowflake_path and os.path.isfile(snowflake_path):
                torrc_content = f"DataDirectory {tor_data_dir}\nSocksPort 127.0.0.1:{self.local_socks_port}\nHTTPTunnelPort 127.0.0.1:{self.local_http_port}\nUseBridges 1\nClientTransportPlugin snowflake exec {snowflake_path}\nBridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.org,ajax.aspnetcdn.com ice=stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn\nBridge snowflake 192.0.2.4:80 8838024498816A039B6BFF4908B6020058B11D18 fingerprint=8838024498816A039B6BFF4908B6020058B11D18 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.org,ajax.aspnetcdn.com ice=stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn\n"
                config_name = "torrc_snowflake"
            elif lyrebird_path and os.path.isfile(lyrebird_path):
                torrc_content = f"DataDirectory {tor_data_dir}\nSocksPort 127.0.0.1:{self.local_socks_port}\nHTTPTunnelPort 127.0.0.1:{self.local_http_port}\nUseBridges 1\nClientTransportPlugin obfs4 exec {lyrebird_path}\nBridge obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1\nBridge obfs4 38.229.1.78:80 C8CBDB2464FC9804A69531437BCF2BE31FDD2EE4 cert=AA1+Qiae9pr5f17V01d3XvqP1TZw5B6G6XG5RZKmYjKPEAo6V0T+AQAU5ADQ iat-mode=1\n"
                config_name = "torrc_obfs4"
            else: return None, None
        else:
            torrc_content = f"DataDirectory {tor_data_dir}\nSocksPort 127.0.0.1:{self.local_socks_port}\nHTTPTunnelPort 127.0.0.1:{self.local_http_port}\n"
            config_name = "torrc_proxy"
            
        with open(os.path.join(self.data_dir, config_name), "w") as f: f.write(torrc_content)
        return config_name, "tor"
