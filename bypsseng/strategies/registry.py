from strategies.adapters.xray import XrayStrategy
from strategies.adapters.singbox import SingboxStrategy
from strategies.adapters.tor import TorStrategy
from strategies.adapters.psiphon import PsiphonStrategy
from strategies.adapters.dnstt import DnsttStrategy

def get_strategy(creds, all_configs=None, dpi_state='none', local_socks_port=None, local_http_port=None, data_dir=None, binary_paths=None):
    proto = creds["protocol"]
    if proto in ("vless", "trojan", "vmess", "ss", "shadowtls", "warp", "warp_over_reality", "cloudflare_worker"):
        return XrayStrategy(creds, all_configs, dpi_state, local_socks_port, local_http_port, data_dir, binary_paths)
    elif proto in ("hysteria2", "hy2", "tuic"):
        return SingboxStrategy(creds, all_configs, dpi_state, local_socks_port, local_http_port, data_dir, binary_paths)
    elif proto in ("tor_proxy", "tor_snowflake"):
        return TorStrategy(creds, all_configs, dpi_state, local_socks_port, local_http_port, data_dir, binary_paths)
    elif proto == "psiphon":
        return PsiphonStrategy(creds, all_configs, dpi_state, local_socks_port, local_http_port, data_dir, binary_paths)
    elif proto == "dnstt":
        return DnsttStrategy(creds, all_configs, dpi_state, local_socks_port, local_http_port, data_dir, binary_paths)
    return None
