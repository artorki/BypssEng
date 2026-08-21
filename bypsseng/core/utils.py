


import os
import sys
import json
import platform
import shutil
import random
import base64
import re
import ipaddress
import logging
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger("NetAnalyzer")




def find_binary(name: str, core_dir: str) -> Optional[str]:
    """Finds the binary executable in the core directory or system PATH."""
    core_path = os.path.join(core_dir, name)
    if platform.system().lower() == 'windows' and not name.endswith('.exe'):
        core_path_exe = core_path + ".exe"
        if os.path.isfile(core_path_exe): return core_path_exe
    if os.path.isfile(core_path): return core_path
        
    pt_dir = os.path.join(core_dir, "pluggable_transports")
    pt_path = os.path.join(pt_dir, name)
    if platform.system().lower() == 'windows' and not name.endswith('.exe'):
        pt_path_exe = pt_path + ".exe"
        if os.path.isfile(pt_path_exe): return pt_path_exe
    if os.path.isfile(pt_path): return pt_path
        
    path = shutil.which(name)
    return path if path else None

def atomic_write_json(filepath: str, data: Dict[str, Any]) -> None:
    """Writes JSON to a temporary file and replaces the original to prevent corruption."""
    tmp_path = filepath + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        os.replace(tmp_path, filepath)
        try: 
            os.chmod(filepath, 0o600) # Restrict permissions for security
        except Exception: 
            pass
    except Exception as e:
        logger.error(f"Failed to write {filepath}: {e}")

def b64_decode(s: str) -> str:
    """Decodes Base64 URL-safe strings with padding correction."""
    s = s.replace('-', '+').replace('_', '/')
    missing = len(s) % 4
    if missing: s += '=' * (4 - missing)
    return base64.b64decode(s).decode('utf-8')




def parse_config_link(link: str) -> Dict[str, Any]:
    """
    Dispatches to specific protocol parsers based on scheme.
    Validates schema before returning (HANDOFF Sec 21, 57).
    Section 65: Does not log raw links to protect credentials.
    """
    try:
        if link.startswith("vmess://"):
            return _parse_vmess(link)
        elif link.startswith("ss://"):
            return _parse_ss(link)
        

        parsed = urlparse(link)
        proto = parsed.scheme
        if not proto:
            return {"protocol": "unsupported", "raw_link": link}
            
        if proto == "vless":
            return _parse_vless(parsed, link)
        elif proto == "trojan":
            return _parse_trojan(parsed, link)
        elif proto in ("hysteria2", "hy2"):
            return _parse_hysteria2(parsed, link)
        elif proto == "tuic":
            return _parse_tuic(parsed, link)
        elif proto in ("naive", "naive+https"):
            return _parse_naive(parsed, link)
        elif proto == "shadowtls":
            return _parse_shadowtls(parsed, link)
        else:
            return {"protocol": "unsupported", "raw_link": link}
            
    except Exception as e:

        logger.error(f"Failed to parse config link. Error: {e}")
        return {"protocol": "unsupported", "raw_link": link}

def _parse_vmess(link: str) -> Dict[str, Any]:
    try:
        raw_b64 = link[8:]
        vmess_data = json.loads(b64_decode(raw_b64))
        creds = {"protocol": "vmess", "raw_link": link}
        creds["vmess_server_ip"] = vmess_data.get("add")
        creds["vmess_port"] = int(vmess_data.get("port", 443))
        creds["vmess_uuid"] = vmess_data.get("id")
        creds["vmess_security"] = vmess_data.get("scy", "auto")
        creds["vmess_type"] = vmess_data.get("net", "tcp")
        creds["vmess_sni"] = vmess_data.get("sni", "")
        creds["vmess_host"] = vmess_data.get("host", "")
        creds["vmess_path"] = unquote(vmess_data.get("path", "/"))
        creds["vmess_service_name"] = vmess_data.get("serviceName", "")
        if not creds["vmess_service_name"] and creds["vmess_type"] == "grpc":
            creds["vmess_service_name"] = creds["vmess_path"]
        creds["vmess_tls"] = vmess_data.get("tls", "")
        creds["vmess_alter_id"] = int(vmess_data.get("aid", 0))
        

        if not creds["vmess_server_ip"] or not creds["vmess_port"] or not creds["vmess_uuid"]:
            raise ValueError("Missing VMess core parameters")
        return creds
    except Exception as e:
        logger.error(f"VMess parse error: {e}")
        return {"protocol": "unsupported", "raw_link": link}

def _parse_ss(link: str) -> Dict[str, Any]:
    try:
        parsed = urlparse(link)
        creds = {"protocol": "ss", "raw_link": link}
        if "@" in parsed.netloc:
            userinfo, hostport = parsed.netloc.rsplit("@", 1)
            if ":" in userinfo:
                method, password = userinfo.split(":", 1)
            else:
                decoded = b64_decode(userinfo)
                method, password = decoded.split(":", 1)
            creds["ss_server_ip"] = parsed.hostname
            creds["ss_port"] = parsed.port
            creds["ss_method"] = method
            creds["ss_password"] = password
        else:
            decoded = b64_decode(parsed.netloc)
            method_pass, hostport = decoded.rsplit("@", 1)
            method, password = method_pass.split(":", 1)
            if hostport.startswith("["):
                ip_str, port_str = hostport.rsplit(":", 1)
                creds["ss_server_ip"] = ip_str.strip("[]")
                creds["ss_port"] = int(port_str)
            else:
                creds["ss_server_ip"] = hostport.split(":")[0]
                creds["ss_port"] = int(hostport.split(":")[1])
            creds["ss_method"] = method
            creds["ss_password"] = password
            
        if not creds.get("ss_server_ip") or not creds.get("ss_port"):
            raise ValueError("Missing SS core parameters")
        return creds
    except Exception as e:
        logger.error(f"SS parse error: {e}")
        return {"protocol": "unsupported", "raw_link": link}

def _parse_vless(parsed, link: str) -> Dict[str, Any]:
    if not parsed.hostname or not parsed.port or not parsed.username:
        raise ValueError("Missing VLESS parameters")
    params = parse_qs(parsed.query)
    creds = {"protocol": "vless", "raw_link": link}
    creds["vless_server_ip"] = parsed.hostname
    creds["vless_port"] = parsed.port
    creds["vless_uuid"] = unquote(parsed.username)
    creds["vless_security"] = params.get("security", ["none"])[0]
    creds["vless_type"] = params.get("type", ["tcp"])[0]
    creds["vless_sni"] = params.get("sni", [""])[0]
    creds["vless_host"] = params.get("host", [""])[0]
    creds["vless_path"] = unquote(params.get("path", ["/"])[0])
    creds["vless_public_key"] = params.get("pbk", [""])[0]
    creds["vless_short_id"] = params.get("sid", [""])[0]
    creds["vless_service_name"] = params.get("serviceName", [""])[0]
    creds["vless_flow"] = params.get("flow", [""])[0]
    return creds

def _parse_trojan(parsed, link: str) -> Dict[str, Any]:
    if not parsed.hostname or not parsed.port or not parsed.username:
        raise ValueError("Missing Trojan parameters")
    params = parse_qs(parsed.query)
    creds = {"protocol": "trojan", "raw_link": link}
    creds["trojan_server_ip"] = parsed.hostname
    creds["trojan_port"] = parsed.port
    creds["trojan_password"] = unquote(parsed.username)
    creds["trojan_domain"] = params.get("sni", [""])[0]
    return creds

def _parse_hysteria2(parsed, link: str) -> Dict[str, Any]:
    if not parsed.hostname or not parsed.port or not parsed.username:
        raise ValueError("Missing Hysteria2 parameters")
    params = parse_qs(parsed.query)
    creds = {"protocol": "hysteria2", "raw_link": link}
    creds["hysteria_server_ip"] = parsed.hostname
    creds["hysteria_port"] = parsed.port
    creds["hysteria_password"] = unquote(parsed.username)
    creds["hysteria_sni"] = params.get("sni", [""])[0]
    creds["hysteria_insecure"] = params.get("insecure", ["0"])[0] == "1"
    creds["hysteria_obfs"] = params.get("obfs", [""])[0]
    creds["hysteria_obfs_password"] = params.get("obfs-password", [""])[0]
    return creds

def _parse_tuic(parsed, link: str) -> Dict[str, Any]:
    if not parsed.hostname or not parsed.port or not parsed.username:
        raise ValueError("Missing TUIC parameters")
    params = parse_qs(parsed.query)
    creds = {"protocol": "tuic", "raw_link": link}
    creds["tuic_server_ip"] = parsed.hostname
    creds["tuic_port"] = parsed.port
    creds["tuic_uuid"] = unquote(parsed.username)
    creds["tuic_password"] = params.get("password", [""])[0]
    creds["tuic_sni"] = params.get("sni", [""])[0]
    creds["tuic_alpn"] = params.get("alpn", ["h3"])[0]
    creds["tuic_insecure"] = params.get("insecure", ["0"])[0] == "1"
    return creds

def _parse_naive(parsed, link: str) -> Dict[str, Any]:
    if not parsed.hostname or not parsed.port or not parsed.username or not parsed.password:
        raise ValueError("Missing Naive parameters")
    params = parse_qs(parsed.query)
    creds = {"protocol": "naive", "raw_link": link}
    creds["naive_server_ip"] = parsed.hostname
    creds["naive_port"] = parsed.port
    creds["naive_user"] = unquote(parsed.username)
    creds["naive_password"] = unquote(parsed.password)
    creds["naive_sni"] = params.get("sni", [""])[0]
    return creds

def _parse_shadowtls(parsed, link: str) -> Dict[str, Any]:
    if not parsed.hostname or not parsed.port or not parsed.username:
        raise ValueError("Missing ShadowTLS parameters")
    params = parse_qs(parsed.query)
    creds = {"protocol": "shadowtls", "raw_link": link}
    creds["shadowtls_server_ip"] = parsed.hostname
    creds["shadowtls_port"] = parsed.port
    creds["shadowtls_password"] = unquote(parsed.username)
    creds["shadowtls_sni"] = params.get("sni", [""])[0]
    return creds




def get_proto_prefix(proto: str) -> str:
    if proto in ("hysteria2", "hy2"): return "hysteria"
    if proto in ("naive+https", "naive"): return "naive"
    return proto

def random_spider_x() -> str:
    paths = ["/", "", "/index.html", "/home", "/api/v1/status", "/static/img/logo.png", "/robots.txt", "/search?q=", "/en/", "/blog/"]
    return random.choice(paths)

def get_less_popular_sni() -> str:
    snis = [
        "www.samsung.com", "www.amd.com", "www.nvidia.com",
        "addons.mozilla.org", "www.icloud.com", "www.tesla.com",
        "www.lovelive-anime.jp", "www.cpanel.net"
    ]
    return random.choice(snis)

def get_dynamic_tls_settings(dpi_state: str = 'none') -> Dict[str, Any]:
    """Returns dynamic TLS settings based on DPI severity."""
    fingerprints = ["chrome", "firefox", "safari", "edge", "ios", "random"]
    if dpi_state in ['dpi_aggressive', 'dpi_rst']:
        lengths = ["10-50", "50-100", "20-80", "100-200"]
        intervals = ["1-3", "3-5", "5-10"]
    else:
        lengths = ["50-100", "100-200", "200-300"]
        intervals = ["5-10", "10-15"]
    return {
        "fingerprint": random.choice(fingerprints),
        "fragment": {"packets": "tlshello", "length": random.choice(lengths), "interval": random.choice(intervals)}
    }