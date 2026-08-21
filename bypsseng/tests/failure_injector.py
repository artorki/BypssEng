from typing import Dict, Any
from bypsseng.domain.conditions import NetworkCondition


class FailureInjector:

    @staticmethod
    def get_scenario(name: str) -> Dict[str, Any]:

        scenarios = {
            "dns_failure": {
                "dns": NetworkCondition.DNS_DROPPED.value,
                "udp": NetworkCondition.UDP_OK.value,
                "dpi": NetworkCondition.DPI_NONE.value,
            },
            "dpi_aggressive": {
                "dns": NetworkCondition.DNS_OK.value,
                "udp": NetworkCondition.UDP_OK.value,
                "dpi": NetworkCondition.DPI_AGGRESSIVE.value,
            },
            "udp_blocked": {
                "dns": NetworkCondition.DNS_OK.value,
                "udp": NetworkCondition.UDP_DROPPED.value,
                "dpi": NetworkCondition.DPI_NONE.value,
            },
            "bandwidth_throttling": {
                "dns": NetworkCondition.DNS_OK.value,
                "udp": NetworkCondition.UDP_OK.value,
                "dpi": NetworkCondition.DPI_NONE.value,
                "speed": NetworkCondition.THROTTLED_INTL.value,
            },
            "unknown_anomaly": {
                "dns": NetworkCondition.DNS_UNKNOWN.value,
                "udp": NetworkCondition.UDP_UNKNOWN.value,
                "dpi": NetworkCondition.DPI_UNKNOWN.value,
            },
            "normal": {
                "dns": NetworkCondition.DNS_OK.value,
                "udp": NetworkCondition.UDP_OK.value,
                "dpi": NetworkCondition.DPI_NONE.value,
                "speed": NetworkCondition.SPEED_OK.value,
            },
        }
        return scenarios.get(name, scenarios["normal"])
