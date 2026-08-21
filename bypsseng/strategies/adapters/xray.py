import os
from strategies.base import Strategy
from core.utils import (
    atomic_write_json,
    get_dynamic_tls_settings,
    random_spider_x,
    get_less_popular_sni,
)
from core.logger import log
from diagnosis.health import scan_clean_cdn_ips
import logging

logger = logging.getLogger("NetAnalyzer")


class XrayStrategy(Strategy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary_name = "xray"

    async def prepare(self) -> tuple:
        creds = self.creds
        log("Action: Generating optimized Xray bypass config...", "SOL")

        routing_rules = {
            "domainStrategy": "AsIs",
            "strictRoute": False,
            "rules": [
                {
                    "type": "field",
                    "outboundTag": "block",
                    "port": "137-139",
                    "network": "tcp,udp",
                },
                {
                    "type": "field",
                    "outboundTag": "block",
                    "ip": ["224.0.0.0/8", "169.254.0.0/16", "255.255.255.255/32"],
                },
                {
                    "type": "field",
                    "outboundTag": "dns-out",
                    "port": 53,
                    "network": "tcp,udp",
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": [
                        "geosite:category-ir",
                        "domain:ir",
                        "domain:bank",
                        "domain:paypal",
                    ],
                },
                {
                    "type": "field",
                    "outboundTag": "direct",
                    "ip": ["geoip:ir", "geoip:private"],
                },
            ],
        }
        dynamic_tls = get_dynamic_tls_settings(self.dpi_state)
        mux_settings = {"enabled": False, "concurrency": -1}

        common_inbounds = [
            {
                "port": self.local_socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            },
            {
                "port": self.local_http_port,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {},
            },
        ]
        common_dns = {
            "servers": ["https+local://8.8.8.8/dns-query", "localhost"],
            "queryStrategy": "UseIP",
        }

        def apply_fragmentation(ob):
            if "streamSettings" not in ob:
                ob["streamSettings"] = {}
            if "sockopt" not in ob["streamSettings"]:
                ob["streamSettings"]["sockopt"] = {}
            ob["streamSettings"]["sockopt"]["dialerProxy"] = "fragment-out"
            ob["streamSettings"]["sockopt"]["tcpNoDelay"] = True
            return ob

        def apply_tcp_nodelay(ob):
            if "streamSettings" not in ob:
                ob["streamSettings"] = {}
            if "sockopt" not in ob["streamSettings"]:
                ob["streamSettings"]["sockopt"] = {}
            ob["streamSettings"]["sockopt"]["tcpNoDelay"] = True
            return ob

        def make_vless_reality_outbound(c, tag="proxy"):
            sni = c.get("vless_sni") or get_less_popular_sni()
            flow = c.get("vless_flow") or "xtls-rprx-vision"
            return apply_fragmentation(
                {
                    "tag": tag,
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": c["vless_server_ip"],
                                "port": c["vless_port"],
                                "users": [
                                    {
                                        "id": c["vless_uuid"],
                                        "encryption": "none",
                                        "flow": flow,
                                    }
                                ],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": sni,
                            "fingerprint": dynamic_tls["fingerprint"],
                            "publicKey": c["vless_public_key"],
                            "shortId": c["vless_short_id"],
                            "spiderX": random_spider_x(),
                        },
                    },
                }
            )

        def make_vless_ws_outbound(c, tag="proxy"):
            host = c.get("vless_host") or c.get("vless_sni", "")
            ob = {
                "tag": tag,
                "protocol": "vless",
                "mux": mux_settings,
                "settings": {
                    "vnext": [
                        {
                            "address": c["vless_server_ip"],
                            "port": c["vless_port"],
                            "users": [{"id": c["vless_uuid"], "encryption": "none"}],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": c.get("vless_security", "none"),
                    "wsSettings": {"path": c["vless_path"], "headers": {"Host": host}},
                },
            }
            return (
                apply_fragmentation(ob)
                if c.get("vless_security") == "tls"
                else apply_tcp_nodelay(ob)
            )

        def make_vless_grpc_outbound(c, tag="proxy"):
            ob = {
                "tag": tag,
                "protocol": "vless",
                "mux": mux_settings,
                "settings": {
                    "vnext": [
                        {
                            "address": c["vless_server_ip"],
                            "port": c["vless_port"],
                            "users": [{"id": c["vless_uuid"], "encryption": "none"}],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "grpc",
                    "security": c.get("vless_security", "none"),
                    "grpcSettings": {"serviceName": c.get("vless_service_name", "")},
                },
            }
            return (
                apply_fragmentation(ob)
                if c.get("vless_security") == "tls"
                else apply_tcp_nodelay(ob)
            )

        def make_trojan_outbound(c, tag="proxy"):
            return apply_fragmentation(
                {
                    "tag": tag,
                    "protocol": "trojan",
                    "mux": mux_settings,
                    "settings": {
                        "servers": [
                            {
                                "address": c["trojan_server_ip"],
                                "port": c["trojan_port"],
                                "password": c["trojan_password"],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": c.get("trojan_domain", ""),
                            "fingerprint": dynamic_tls["fingerprint"],
                            "minVersion": "1.2",
                        },
                    },
                }
            )

        def make_shadowtls_outbound(c, tag="proxy"):
            return apply_fragmentation(
                {
                    "tag": tag,
                    "protocol": "shadowtls",
                    "settings": {
                        "servers": [
                            {
                                "address": c["shadowtls_server_ip"],
                                "port": c["shadowtls_port"],
                                "password": c["shadowtls_password"],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": c.get("shadowtls_sni", "")
                            or get_less_popular_sni(),
                            "fingerprint": dynamic_tls["fingerprint"],
                            "minVersion": "1.2",
                        },
                    },
                }
            )

        def make_vmess_outbound(c, tag="proxy"):
            ob = {
                "tag": tag,
                "protocol": "vmess",
                "mux": mux_settings,
                "settings": {
                    "vnext": [
                        {
                            "address": c["vmess_server_ip"],
                            "port": c["vmess_port"],
                            "users": [
                                {
                                    "id": c["vmess_uuid"],
                                    "security": c["vmess_security"],
                                    "alterId": c.get("vmess_alter_id", 0),
                                }
                            ],
                        }
                    ]
                },
            }
            stream = {"network": c["vmess_type"]}
            if c["vmess_type"] == "ws":
                stream["wsSettings"] = {
                    "path": c["vmess_path"],
                    "headers": {"Host": c["vmess_host"] or c["vmess_sni"]},
                }
            elif c["vmess_type"] == "grpc":
                stream["grpcSettings"] = {
                    "serviceName": c.get("vmess_service_name", "")
                }
            elif c["vmess_type"] == "http":
                stream["httpSettings"] = {
                    "path": c["vmess_path"],
                    "host": [c["vmess_host"]],
                }
            if c["vmess_tls"] == "tls":
                stream["security"] = "tls"
                stream["tlsSettings"] = {
                    "serverName": c["vmess_sni"],
                    "fingerprint": dynamic_tls["fingerprint"],
                    "minVersion": "1.2",
                }
                ob["streamSettings"] = stream
                return apply_fragmentation(ob)
            else:
                stream["security"] = "none"
                ob["streamSettings"] = stream
                return apply_tcp_nodelay(ob)

        def make_ss_outbound(c, tag="proxy"):
            return apply_tcp_nodelay(
                {
                    "tag": tag,
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [
                            {
                                "address": c["ss_server_ip"],
                                "port": c["ss_port"],
                                "method": c["ss_method"],
                                "password": c["ss_password"],
                            }
                        ]
                    },
                }
            )

        def make_outbound_for(c, tag="proxy"):
            if c["protocol"] == "vless":
                if c.get("vless_security") == "reality":
                    return make_vless_reality_outbound(c, tag)
                elif c.get("vless_type") == "ws":
                    return make_vless_ws_outbound(c, tag)
                elif c.get("vless_type") == "grpc":
                    return make_vless_grpc_outbound(c, tag)
                elif c.get("vless_type") == "tcp":
                    ob = {
                        "tag": tag,
                        "protocol": "vless",
                        "mux": mux_settings,
                        "settings": {
                            "vnext": [
                                {
                                    "address": c["vless_server_ip"],
                                    "port": c["vless_port"],
                                    "users": [
                                        {"id": c["vless_uuid"], "encryption": "none"}
                                    ],
                                }
                            ]
                        },
                        "streamSettings": {"network": "tcp"},
                    }
                    if c.get("vless_security") == "tls":
                        ob["streamSettings"]["security"] = "tls"
                        ob["streamSettings"]["tlsSettings"] = {
                            "serverName": c.get("vless_sni", ""),
                            "fingerprint": dynamic_tls["fingerprint"],
                            "minVersion": "1.2",
                        }
                        return apply_fragmentation(ob)
                    else:
                        ob["streamSettings"]["security"] = "none"
                        return apply_tcp_nodelay(ob)
            elif c["protocol"] == "trojan":
                return make_trojan_outbound(c, tag)
            elif c["protocol"] == "shadowtls":
                return make_shadowtls_outbound(c, tag)
            elif c["protocol"] == "vmess":
                return make_vmess_outbound(c, tag)
            elif c["protocol"] == "ss":
                return make_ss_outbound(c, tag)

        if creds["protocol"] == "warp_over_reality":
            warp_data = creds.get("warp_data")
            reality_config = creds.get("reality_config")
            if not warp_data or not reality_config:
                return None, None
            flow = reality_config.get("vless_flow") or "xtls-rprx-vision"
            sni_val = reality_config.get("vless_sni") or get_less_popular_sni()
            reality_outbound = apply_fragmentation(
                {
                    "tag": "reality_tunnel",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": reality_config["vless_server_ip"],
                                "port": reality_config["vless_port"],
                                "users": [
                                    {
                                        "id": reality_config["vless_uuid"],
                                        "encryption": "none",
                                        "flow": flow,
                                    }
                                ],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": sni_val,
                            "publicKey": reality_config["vless_public_key"],
                            "shortId": reality_config["vless_short_id"],
                            "spiderX": random_spider_x(),
                        },
                    },
                }
            )
            warp_outbound = {
                "tag": "proxy",
                "protocol": "wireguard",
                "proxySettings": {"tag": "reality_tunnel"},
                "settings": {
                    "secretKey": warp_data.get("private_key", ""),
                    "address": [
                        warp_data.get("ipv4_address", ""),
                        warp_data.get("ipv6_address", ""),
                    ],
                    "peers": [
                        {
                            "publicKey": warp_data.get("peer_public_key", ""),
                            "allowedIPs": ["0.0.0.0/0", "::/0"],
                            "endpoint": "162.159.192.1:2408",
                        }
                    ],
                    "reserved": warp_data.get("reserved", [0, 0, 0]),
                    "kernelMode": False,
                },
            }
            config = {
                "log": {"loglevel": "warning"},
                "dns": common_dns,
                "inbounds": common_inbounds,
                "outbounds": [
                    warp_outbound,
                    reality_outbound,
                    {"tag": "dns-out", "protocol": "dns"},
                    {"tag": "direct", "protocol": "freedom"},
                ],
                "routing": routing_rules,
            }
            atomic_write_json(
                os.path.join(self.data_dir, "auto_bypass_config_warp_reality.json"),
                config,
            )
            self._config_file = "auto_bypass_config_warp_reality.json"
            return self._config_file, "xray"

        if creds["protocol"] == "warp":
            warp_data = creds.get("warp_data")
            if not warp_data:
                return None, None
            endpoint = creds.get(
                "custom_endpoint", warp_data.get("endpoint", "162.159.192.1:2408")
            )
            config = {
                "log": {"loglevel": "warning"},
                "dns": common_dns,
                "inbounds": common_inbounds,
                "outbounds": [
                    {
                        "tag": "proxy",
                        "protocol": "wireguard",
                        "settings": {
                            "secretKey": warp_data.get("private_key", ""),
                            "address": [
                                warp_data.get("ipv4_address", ""),
                                warp_data.get("ipv6_address", ""),
                            ],
                            "peers": [
                                {
                                    "publicKey": warp_data.get("peer_public_key", ""),
                                    "allowedIPs": ["0.0.0.0/0", "::/0"],
                                    "endpoint": endpoint,
                                }
                            ],
                            "reserved": warp_data.get("reserved", [0, 0, 0]),
                            "kernelMode": False,
                            "mtu": 1280,
                        },
                    },
                    {"tag": "dns-out", "protocol": "dns"},
                    {"tag": "direct", "protocol": "freedom"},
                ],
                "routing": routing_rules,
            }
            atomic_write_json(
                os.path.join(self.data_dir, "auto_bypass_config_warp.json"), config
            )
            self._config_file = "auto_bypass_config_warp.json"
            return self._config_file, "xray"

        if creds["protocol"] == "cloudflare_worker":
            worker_data = creds.get("worker_data")
            if (
                not worker_data
                or not worker_data.get("id")
                or not worker_data.get("host")
            ):
                return None, None
            worker_host = worker_data["host"]
            worker_id = worker_data["id"]
            worker_path = worker_data.get("path", "/ws")
            cf_ip = None
            cdn_provider = worker_data.get("cdn", "cloudflare")
            clean_ips = await scan_clean_cdn_ips(
                cdn_provider=cdn_provider,
                worker_host=worker_host,
                worker_path=worker_path,
                count=3,
            )
            if clean_ips:
                cf_ip = clean_ips[0]
            if not cf_ip:
                return None, None
            config = {
                "log": {"loglevel": "warning"},
                "dns": common_dns,
                "inbounds": common_inbounds,
                "outbounds": [
                    {
                        "tag": "proxy",
                        "protocol": "vless",
                        "mux": mux_settings,
                        "settings": {
                            "vnext": [
                                {
                                    "address": cf_ip,
                                    "port": 443,
                                    "users": [{"id": worker_id, "encryption": "none"}],
                                }
                            ]
                        },
                        "streamSettings": {
                            "network": "ws",
                            "security": "tls",
                            "tlsSettings": {
                                "serverName": worker_host,
                                "fingerprint": dynamic_tls["fingerprint"],
                                "minVersion": "1.2",
                            },
                            "wsSettings": {
                                "path": worker_path,
                                "headers": {"Host": worker_host},
                            },
                        },
                    }
                ],
                "routing": routing_rules,
            }
            config["outbounds"][0] = apply_fragmentation(config["outbounds"][0])
            config["outbounds"].append(
                {
                    "tag": "fragment-out",
                    "protocol": "freedom",
                    "settings": {"fragment": dynamic_tls["fragment"]},
                    "streamSettings": {"sockopt": {"tcpNoDelay": True}},
                }
            )
            atomic_write_json(
                os.path.join(self.data_dir, "auto_bypass_config_cf.json"), config
            )
            self._config_file = "auto_bypass_config_cf.json"
            return self._config_file, "xray"

        use_balancer = self.all_configs and len(self.all_configs) > 1
        config = {
            "log": {"loglevel": "warning"},
            "dns": common_dns,
            "inbounds": common_inbounds,
            "outbounds": [],
            "routing": routing_rules,
        }

        if self.dpi_state in ["dpi_aggressive", "dpi_rst", "drop"] and self.all_configs:
            shadowtls_cfg = next(
                (c for c in self.all_configs if c["protocol"] == "shadowtls"), None
            )
            if shadowtls_cfg and creds["protocol"] not in ("shadowtls",):
                outer_ob = make_shadowtls_outbound(
                    shadowtls_cfg, "outer_shadowtls_layer"
                )
                if outer_ob:
                    config["outbounds"].append(outer_ob)
                    inner_ob = make_outbound_for(creds, "proxy")
                    if inner_ob:
                        if "streamSettings" not in inner_ob:
                            inner_ob["streamSettings"] = {}
                        if "sockopt" not in inner_ob["streamSettings"]:
                            inner_ob["streamSettings"]["sockopt"] = {}
                        inner_ob["streamSettings"]["sockopt"][
                            "dialerProxy"
                        ] = "outer_shadowtls_layer"
                        config["outbounds"].append(inner_ob)
                        config["outbounds"].append(
                            {
                                "tag": "fragment-out",
                                "protocol": "freedom",
                                "settings": {"fragment": dynamic_tls["fragment"]},
                                "streamSettings": {"sockopt": {"tcpNoDelay": True}},
                            }
                        )
                        config["outbounds"].extend(
                            [
                                {"tag": "dns-out", "protocol": "dns"},
                                {"tag": "direct", "protocol": "freedom"},
                                {"tag": "block", "protocol": "blackhole"},
                            ]
                        )
                        atomic_write_json(
                            os.path.join(self.data_dir, "auto_bypass_config_xray.json"),
                            config,
                        )
                        self._config_file = "auto_bypass_config_xray.json"
                        return self._config_file, "xray"

            reality_cfg = next(
                (
                    c
                    for c in self.all_configs
                    if c["protocol"] == "vless" and c.get("vless_security") == "reality"
                ),
                None,
            )
            if reality_cfg and creds["protocol"] not in ("vless", "reality"):
                outer_ob = make_vless_reality_outbound(
                    reality_cfg, "outer_reality_layer"
                )
                if outer_ob:
                    config["outbounds"].append(outer_ob)
                    inner_ob = make_outbound_for(creds, "proxy")
                    if inner_ob:
                        if "streamSettings" not in inner_ob:
                            inner_ob["streamSettings"] = {}
                        if "sockopt" not in inner_ob["streamSettings"]:
                            inner_ob["streamSettings"]["sockopt"] = {}
                        inner_ob["streamSettings"]["sockopt"][
                            "dialerProxy"
                        ] = "outer_reality_layer"
                        config["outbounds"].append(inner_ob)
                        config["outbounds"].append(
                            {
                                "tag": "fragment-out",
                                "protocol": "freedom",
                                "settings": {"fragment": dynamic_tls["fragment"]},
                                "streamSettings": {"sockopt": {"tcpNoDelay": True}},
                            }
                        )
                        config["outbounds"].extend(
                            [
                                {"tag": "dns-out", "protocol": "dns"},
                                {"tag": "direct", "protocol": "freedom"},
                                {"tag": "block", "protocol": "blackhole"},
                            ]
                        )
                        atomic_write_json(
                            os.path.join(self.data_dir, "auto_bypass_config_xray.json"),
                            config,
                        )
                        self._config_file = "auto_bypass_config_xray.json"
                        return self._config_file, "xray"

        if use_balancer:
            balancer_tags = []
            for idx, c in enumerate(self.all_configs):
                tag = f"proxy_{idx}"
                ob = make_outbound_for(c, tag)
                if ob:
                    ob = apply_fragmentation(ob)
                    config["outbounds"].append(ob)
                    balancer_tags.append(tag)
            if balancer_tags:
                config["routing"]["balancers"] = [
                    {
                        "tag": "balancer",
                        "selector": balancer_tags,
                        "fallbackTag": balancer_tags[0],
                        "strategy": {"type": "leastPing"},
                    }
                ]
                config["routing"]["rules"].insert(
                    0,
                    {"type": "field", "balancerTag": "balancer", "network": "tcp,udp"},
                )
                config["observatory"] = {
                    "subjectSelect": balancer_tags,
                    "probeURL": "https://www.gstatic.com/generate_204",
                    "probeInterval": "30s",
                    "enableConcurrency": True,
                }
            else:
                ob = make_outbound_for(creds, "proxy")
                if ob:
                    config["outbounds"].append(ob)
        else:
            ob = make_outbound_for(creds, "proxy")
            if not ob:
                return None, None
            config["outbounds"].append(ob)

        config["outbounds"].append(
            {
                "tag": "fragment-out",
                "protocol": "freedom",
                "settings": {"fragment": dynamic_tls["fragment"]},
                "streamSettings": {"sockopt": {"tcpNoDelay": True}},
            }
        )
        config["outbounds"].extend(
            [
                {"tag": "dns-out", "protocol": "dns"},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ]
        )
        atomic_write_json(
            os.path.join(self.data_dir, "auto_bypass_config_xray.json"), config
        )
        self._config_file = "auto_bypass_config_xray.json"
        return self._config_file, "xray"
