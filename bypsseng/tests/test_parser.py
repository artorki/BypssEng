


import pytest
import base64
import json
from core.utils import parse_config_link

def test_parse_vless_valid():
    """Test parsing a valid VLESS Reality link."""
    link = "vless://123e4567-e89b-12d3-a456-426614174000@host.com:443?security=reality&sni=sni.com&pbk=pubkey&sid=shortid&type=tcp"
    creds = parse_config_link(link)
    
    assert creds["protocol"] == "vless"
    assert creds["vless_server_ip"] == "host.com"
    assert creds["vless_port"] == 443
    assert creds["vless_uuid"] == "123e4567-e89b-12d3-a456-426614174000"
    assert creds["vless_security"] == "reality"

def test_parse_vmess_valid():
    """
    Section 21: Test parsing a valid VMess link (Base64 JSON format).
    This was broken in old versions due to generic URL parsing assumptions.
    """
    vmess_json = {
        "add": "host.com", "port": "443", "id": "123e4567-e89b-12d3-a456-426614174000",
        "aid": "0", "net": "tcp", "type": "none"
    }
    b64_str = base64.b64encode(json.dumps(vmess_json).encode()).decode()
    link = f"vmess://{b64_str}"
    
    creds = parse_config_link(link)
    
    assert creds["protocol"] == "vmess"
    assert creds["vmess_server_ip"] == "host.com"
    assert creds["vmess_port"] == 443
    assert creds["vmess_uuid"] == "123e4567-e89b-12d3-a456-426614174000"

def test_parse_ss_valid():
    """Test parsing a valid Shadowsocks link."""
    link = "ss://aes-256-gcm:password@host.com:443"
    creds = parse_config_link(link)
    
    assert creds["protocol"] == "ss"
    assert creds["ss_server_ip"] == "host.com"
    assert creds["ss_port"] == 443
    assert creds["ss_method"] == "aes-256-gcm"
    assert creds["ss_password"] == "password"

def test_parse_trojan_valid():
    """Test parsing a valid Trojan link."""
    link = "trojan://password@host.com:443?sni=sni.com"
    creds = parse_config_link(link)
    
    assert creds["protocol"] == "trojan"
    assert creds["trojan_server_ip"] == "host.com"
    assert creds["trojan_port"] == 443
    assert creds["trojan_password"] == "password"
    assert creds["trojan_domain"] == "sni.com"

def test_parse_hysteria2_valid():
    """Test parsing a valid Hysteria2 link."""
    link = "hysteria2://password@host.com:443?sni=sni.com&insecure=1"
    creds = parse_config_link(link)
    
    assert creds["protocol"] == "hysteria2"
    assert creds["hysteria_server_ip"] == "host.com"
    assert creds["hysteria_port"] == 443
    assert creds["hysteria_password"] == "password"
    assert creds["hysteria_sni"] == "sni.com"
    assert creds["hysteria_insecure"] == True

def test_parse_invalid_vless_missing_port():
    """
    Section 57: Configuration Validation.
    Invalid VLESS link missing port should return unsupported.
    """
    link = "vless://uuid@host.com?security=reality"
    creds = parse_config_link(link)
    
    assert creds["protocol"] == "unsupported"

def test_parse_invalid_vmess_missing_uuid():
    """
    Section 57: Semantic validation for VMess.
    Missing UUID should return unsupported.
    """
    vmess_json = {"add": "host.com", "port": "443", "id": "", "aid": "0"}
    b64_str = base64.b64encode(json.dumps(vmess_json).encode()).decode()
    link = f"vmess://{b64_str}"
    
    creds = parse_config_link(link)
    
    assert creds["protocol"] == "unsupported"

def test_parse_unsupported_protocol():
    """Test an unknown protocol."""
    link = "unknown://something"
    creds = parse_config_link(link)
    
    assert creds["protocol"] == "unsupported"