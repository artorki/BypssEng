from pydantic import BaseModel, Field, field_validator
from typing import List, Tuple
import logging

logger = logging.getLogger("NetAnalyzer")


class IntervalsConfig(BaseModel):
    test_loop: int = Field(
        default=120,
        description="Interval between full diagnosis cycles when network is stable.",
    )
    blackout_loop: int = Field(
        default=300,
        description="Interval between tests when network is completely blacked out.",
    )
    tcp_timeout: int = Field(default=7, description="Timeout for TCP connection tests.")
    dns_timeout: int = Field(default=5, description="Timeout for DNS resolution tests.")
    http_timeout: int = Field(
        default=10, description="Timeout for general HTTP requests."
    )
    global_test_timeout: int = Field(
        default=45, description="Maximum time allowed for a full diagnosis phase."
    )

    @field_validator(
        "tcp_timeout",
        "dns_timeout",
        "http_timeout",
        "global_test_timeout",
        "test_loop",
        "blackout_loop",
    )
    @classmethod
    def check_positive_timeout(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Timeout and loop intervals must be greater than 0")
        return v


class TargetsConfig(BaseModel):
    external_ips: List[str] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    internal_ips: List[str] = ["217.218.127.127", "217.218.155.155"]
    cf_ip: str = "104.16.123.96"
    google_ip: str = "142.250.190.46"
    national_speed_urls: List[str] = [
        "https://speedtest.rahkasam.ir/5MB.bin",
        "http://speedtest.ircf.net/5MB.bin",
        "http://speedtest.pishgaman.net/5MB.bin",
    ]
    international_speed_urls: List[str] = [
        "https://speed.cloudflare.com/__down?bytes=5000000",
        "https://speed.hetzner.de/5MB.bin",
        "https://cachefly.cachefly.net/5mb.test",
    ]
    doh_endpoints: List[str] = [
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/dns-query",
        "https://9.9.9.9/dns-query",
    ]
    captive_portal_url: str = "http://detectportal.firefox.com/canonical.html"
    ipv6_target: str = "2606:4700:4700::1111"
    dns_candidates: List[str] = [
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
        "9.9.9.10",
        "94.140.14.14",
        "94.140.15.15",
        "217.218.127.127",
        "217.218.155.155",
        "91.92.255.244",
    ]


class ThresholdsConfig(BaseModel):
    speed_kbps_severe: int = Field(
        default=20, description="Threshold for severely throttled speed."
    )
    speed_kbps_slow: int = Field(default=500, description="Threshold for slow speed.")
    speed_test_samples: int = Field(
        default=3, description="Number of samples to take for speed tests."
    )
    speed_test_bytes: int = Field(
        default=2000000, description="Amount of data to download for speed test."
    )
    speed_test_max_duration: int = Field(
        default=5, description="Maximum duration in seconds for a speed test."
    )

    @field_validator("speed_test_samples")
    @classmethod
    def check_samples(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Samples must be greater than 0")
        return v


class CdnRangesConfig(BaseModel):
    cloudflare: List[Tuple[int, int]] = [
        (104, 16),
        (172, 64),
        (162, 159),
        (104, 17),
        (104, 18),
    ]
    gcore: List[Tuple[int, int]] = [(92, 223), (185, 188), (45, 133)]
    aws: List[str] = ["18.160.0.1", "13.224.0.1", "99.84.0.1"]


class AppConfig(BaseModel):
    intervals: IntervalsConfig = IntervalsConfig()
    targets: TargetsConfig = TargetsConfig()
    thresholds: ThresholdsConfig = ThresholdsConfig()
    cdn_ranges: CdnRangesConfig = CdnRangesConfig()


CONFIG = AppConfig()
