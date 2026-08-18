import os
from strategies.base import Strategy
from core.utils import atomic_write_json, get_dynamic_tls_settings, random_spider_x, get_less_popular_sni
from core.logger import log
from diagnosis.health import scan_clean_cdn_ips

class XrayStrategy(Strategy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary_name = "xray"

    async def prepare(self):
        creds = self.creds
        log("Action: Generating optimized Xray bypass config (Core Clustering & Secure Split Tunneling)...", "SOL")
        
        routing_rules = {
            "domainStrategy": "AsIs", "strictRoute": False,
            "rules": [
                {"type": "field", "outboundTag": "block", "port": "137-139", "network": "tcp,udp"},
                {"type": "field", "outboundTag": "block", "ip": ["224.0.0.0/8", "169.254.0.0/16", "255.255.255.255/32"]},
                {"type": "field", "outboundTag": "dns-out", "port": 53, "network": "tcp,udp"},
                {"type": "field", "outboundTag": "direct", "domain": ["geosite:category-ir", "domain:ir", "domain:bank", "domain:paypal"]},
                {"type": "field", "outboundTag": "direct", "ip": ["geoip:ir", "geoip:private"]}
            ]
        }
        dynamic_tls = get_dynamic_tls_settings(self.dpi_state)
        mux_settings = {"enabled": False, "concurrency": -1}
        
        common_inbounds = [
            {"port": self.local_socks_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}, "tag": "socks_in"},
            {"port": self.local_http_port, "listen": "127.0.0.1", "protocol": "http", "settings": {}, "tag": "http_in"}
        ]
        common_dns = {"servers": ["https+local://8.8.8.8/dns-query", "localhost"], "queryStrategy": "UseIP"}

        def apply_fragmentation(ob, fragment_val=None):
            if "streamSettings" not in ob: ob["streamSettings"] = {}
            if "sockopt" not in ob["streamSettings"]: ob["streamSettings"]["sockopt"] = {}
            if fragment_val:
                ob["streamSettings"]["sockopt"]["dialerProxy"] = "fragment-out"
            ob["streamSettings"]["sockopt"]["tcpNoDelay"] = True
            return ob

        def make_outbound(c, tag="proxy"):
            sni = c.get("vless_sni") or get_less_popular_sni()
            flow = c.get("vless_flow") or "xtls-rprx-vision"
            return apply_fragmentation({"tag": tag, "protocol": "vless", "settings": {"vnext": [{"address": c["vless_server_ip"], "port": c["vless_port"], "users": [{"id": c["vless_uuid"], "encryption": "none", "flow": flow}]}]}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": sni, "fingerprint": "chrome", "publicKey": c["vless_public_key"], "shortId": c["vless_short_id"], "spiderX": random_spider_x()}}})

        outbounds = [
            make_outbound(creds, "proxy_main"),
            make_outbound(creds, "proxy_light"),
            make_outbound(creds, "proxy_heavy")
        ]
        
        routing_rules["balancers"] = [{"tag": "balancer", "selector": ["proxy_main", "proxy_light", "proxy_heavy"], "fallbackTag": "proxy_main", "strategy": {"type": "leastPing"}}]
        routing_rules["rules"].insert(0, {"type": "field", "balancerTag": "balancer", "network": "tcp,udp"})
        
        outbounds.append({"tag": "fragment-out", "protocol": "freedom", "settings": {"fragment": dynamic_tls["fragment"]}, "streamSettings": {"sockopt": {"tcpNoDelay": True}}})
        outbounds.extend([{"tag": "dns-out", "protocol": "dns"}, {"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}])
        
        config = {
            "log": {"loglevel": "warning"}, 
            "dns": common_dns, 
            "inbounds": common_inbounds, 
            "outbounds": outbounds, 
            "routing": routing_rules,
            "observatory": {
                "subjectSelect": ["proxy_main", "proxy_light", "proxy_heavy"], 
                "probeURL": "https://www.gstatic.com/generate_204", 
                "probeInterval": "30s", 
                "enableConcurrency": True
            }
        }
        
        atomic_write_json(os.path.join(self.data_dir, "auto_bypass_config_xray.json"), config)
        return "auto_bypass_config_xray.json", "xray"
