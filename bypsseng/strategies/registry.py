from strategies.adapters.xray import XrayStrategy
from strategies.adapters.hysteria import HysteriaStrategy
from strategies.adapters.tuic import TuicStrategy
from strategies.adapters.naive import NaiveStrategy
from strategies.adapters.tor import TorStrategy
from strategies.adapters.psiphon import PsiphonStrategy
from strategies.adapters.dnstt import DnsttStrategy

def get_strategy(creds, all_configs=None, dpi_state='none', local_socks_port=None, local_http_port=None, data_dir=None):
    proto = creds["protocol"]
    if proto in ("vless", "trojan", "vmess", "ss", "shadowtls", "warp", "warp_over_reality", "cloudflare_worker"):
        return XrayStrategy(creds, all_configs, dpi_state, local_socks_port, local_http_port, data_dir)
    elif proto in ("hysteria2", "hy2"):
        return HysteriaStrategy(creds, all_configs, dpi_state, local_socks_port, local_http_port, data_dir)
    elif proto == "tuic":
        return TuicStrategy(creds, all_configs, dpi_state, local_socks_port, local_http_port, data_dir)
    elif proto in ("naive+https", "naive"):
        return NaiveStrategy(creds, all_configs, dpi_state, local_socks_port, local_http_port, data_dir)
    elif proto in ("tor_proxy", "tor_snowflake"):
        return TorStrategy(creds, all_configs, dpi_state, local_socks_port, local_http_port, data_dir)
    elif proto == "psiphon":
        return PsiphonStrategy(creds, all_configs, dpi_state, local_socks_port, local_http_port, data_dir)
    elif proto == "dnstt":
        return DnsttStrategy(creds, all_configs, dpi_state, local_socks_port, local_http_port, data_dir)
    return None
