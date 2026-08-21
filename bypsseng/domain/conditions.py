
from enum import Enum





class NetworkCondition(Enum):

    HEALTHY = "healthy"
    CAPTIVE_PORTAL = "captive_portal"


    DNS_OK = "dns_ok"
    DNS_DROPPED = "dns_dropped"
    DNS_HIJACKED = "dns_hijacked"
    DNS_SYSTEM_BROKEN = "dns_system_broken"
    UDP_DNS_BLOCKED = "udp_dns_blocked"
    DNS_UNKNOWN = "dns_unknown"           # Section 27


    DPI_NONE = "dpi_none"
    DPI_RST = "dpi_rst"
    DPI_AGGRESSIVE = "dpi_aggressive"
    DPI_UNKNOWN = "dpi_unknown"           # Section 27


    SPEED_OK = "speed_ok"
    SPEED_SLOW = "speed_slow"
    THROTTLED_INTL = "throttled_intl"
    INTL_CUT = "intl_cut"
    SPEED_FAILED = "speed_failed"         # Section 27: Insufficient data


    UDP_OK = "udp_ok"
    UDP_DROPPED = "udp_dropped"
    UDP_UNKNOWN = "udp_unknown"           # Section 27


    WARP_OK = "warp_ok"
    WARP_PARTIAL = "warp_partial"
    WARP_DROPPED = "warp_dropped"
    QUIC_REACHABLE = "quic_reachable"
    QUIC_DROPPED = "quic_dropped"
    QUIC_UNKNOWN = "quic_unknown"         # Section 27


    VPN_OK = "vpn_ok"
    VPN_PARTIAL = "vpn_partial"
    VPN_BLOCKED = "vpn_blocked"
    VPN_UNKNOWN = "vpn_unknown"           # Section 27






class ConditionClassification(Enum):
    KNOWN_CONDITION = "known_condition"
    UNKNOWN_ANOMALY = "unknown_anomaly"
    INSUFFICIENT_DATA = "insufficient_data"
    CONFLICTING_OBSERVATIONS = "conflicting_observations"

def classify_condition(condition_str: str) -> ConditionClassification:
    """
    Maps raw condition strings to canonical classifications.
    Used by the Decision Engine to handle unknown states safely.
    """
    if condition_str in [
        NetworkCondition.DNS_UNKNOWN.value,
        NetworkCondition.DPI_UNKNOWN.value,
        NetworkCondition.UDP_UNKNOWN.value,
        NetworkCondition.VPN_UNKNOWN.value,
        NetworkCondition.QUIC_UNKNOWN.value
    ]:
        return ConditionClassification.UNKNOWN_ANOMALY
        
    if condition_str in [
        NetworkCondition.SPEED_FAILED.value
    ]:
        return ConditionClassification.INSUFFICIENT_DATA
        
    return ConditionClassification.KNOWN_CONDITION