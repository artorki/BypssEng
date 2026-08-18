from pydantic import BaseModel, validator
from typing import List, Tuple

class IntervalsConfig(BaseModel):
    test_loop: int = 120
    blackout_loop: int = 300
    tcp_timeout: int = 7
    dns_timeout: int = 5
    http_timeout: int = 10
    global_test_timeout: int = 45

    @validator('tcp_timeout', 'dns_timeout', 'http_timeout', 'global_test_timeout', 'test_loop', 'blackout_loop')
    def check_positive_timeout(cls, v):
        if v <= 0:
            raise ValueError("Timeout and loop intervals must be greater than 0")
        return v

class TargetsConfig(BaseModel):
    external_ips: List[str] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    internal_ips: List[str] = ["217.218.127.127", "217.218.155.155"]
    cf_ip: str = "104.16.123.96"
    google_ip: str = "142.250.190.46"
    national_speed_urls: List[str] = ["https://speedtest.rahkasam.ir/5MB.bin", "http://speedtest.ircf.net/5MB.bin", "http://speedtest.pishgaman.net/5MB.bin"]
    international_speed_urls: List[str] = ["https://speed.cloudflare.com/__down?bytes=5000000", "https://speed.hetzner.de/5MB.bin", "https://cachefly.cachefly.net/5mb.test"]
    doh_endpoints: List[str] = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"]
    captive_portal_url: str = "http://detectportal.firefox.com/canonical.html"
    ipv6_target: str = "2606:4700:4700::1111"
    dns_candidates: List[str] = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "9.9.9.10", "94.140.14.14", "94.140.15.15", "217.218.127.127", "217.218.155.155", "91.92.255.244"]

class ThresholdsConfig(BaseModel):
    speed_kbps_severe: int = 20
    speed_kbps_slow: int = 500
    speed_test_samples: int = 3
    speed_test_bytes: int = 2000000
    speed_test_max_duration: int = 5

    @validator('speed_test_samples')
    def check_samples(cls, v):
        if v <= 0:
            raise ValueError("Samples must be greater than 0")
        return v

class CdnRangesConfig(BaseModel):
    cloudflare: List[Tuple[int, int]] = [(104,16), (172,64), (162,159), (104,17), (104,18)]
    gcore: List[Tuple[int, int]] = [(92,223), (185,188), (45,133)]
    aws: List[str] = ["18.160.0.1", "13.224.0.1", "99.84.0.1"]

class AppConfig(BaseModel):
    intervals: IntervalsConfig = IntervalsConfig()
    targets: TargetsConfig = TargetsConfig()
    thresholds: ThresholdsConfig = ThresholdsConfig()
    cdn_ranges: CdnRangesConfig = CdnRangesConfig()

CONFIG = AppConfig()
