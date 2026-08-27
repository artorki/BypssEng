from engine.rule_engine import RuleEngine
from bypsseng.domain.models import DiagnosisResult
from bypsseng.domain.conditions import NetworkCondition
import logging

logger = logging.getLogger("NetAnalyzer")


def setup_decision_rules():
    engine = RuleEngine()

    engine.add_rule(
        lambda s: s.get("captive", False) == True,
        lambda s: DiagnosisResult(
            condition=NetworkCondition.CAPTIVE_PORTAL.value,
            confidence=1.0,
            evidence=["captive_portal_detected"],
            severity="high",
        ),
    )

    engine.add_rule(
        lambda s: s.get("dns")
        in [
            NetworkCondition.DNS_DROPPED.value,
            NetworkCondition.DNS_HIJACKED.value,
            NetworkCondition.UDP_DNS_BLOCKED.value,
        ],
        lambda s: DiagnosisResult(
            condition=NetworkCondition.DNS_INTERFERENCE.value,
            confidence=0.9,
            evidence=["dns_disruption_detected", f"dns_state={s.get('dns')}"],
            severity="high",
        ),
    )

    engine.add_rule(
        lambda s: s.get("dns") == NetworkCondition.DNS_UNKNOWN.value,
        lambda s: DiagnosisResult(
            condition=NetworkCondition.DNS_INTERFERENCE.value,
            confidence=0.6,
            evidence=["dns_state_unclear", "treating_as_potential_interference"],
            severity="medium",
        ),
    )

    engine.add_rule(
        lambda s: s.get("dpi")
        in [NetworkCondition.DPI_AGGRESSIVE.value, NetworkCondition.DPI_RST.value],
        lambda s: DiagnosisResult(
            condition=NetworkCondition.DPI_FILTERING.value,
            confidence=0.85,
            evidence=["sni_filtering_detected", f"dpi_state={s.get('dpi')}"],
            severity="high",
        ),
    )

    engine.add_rule(
        lambda s: s.get("dpi") == NetworkCondition.DPI_UNKNOWN.value,
        lambda s: DiagnosisResult(
            condition=NetworkCondition.DPI_FILTERING.value,
            confidence=0.6,
            evidence=["dpi_state_unclear", "treating_as_potential_filtering"],
            severity="medium",
        ),
    )

    engine.add_rule(
        lambda s: s.get("speed")
        in [
            NetworkCondition.THROTTLED_INTL.value,
            NetworkCondition.SPEED_SLOW.value,
            NetworkCondition.INTL_CUT.value,
        ],
        lambda s: DiagnosisResult(
            condition=NetworkCondition.BANDWIDTH_THROTTLING.value,
            confidence=0.75,
            evidence=["international_speed_low", f"speed_state={s.get('speed')}"],
            severity="medium",
        ),
    )

    engine.add_rule(
        lambda s: s.get("udp") == NetworkCondition.UDP_DROPPED.value,
        lambda s: DiagnosisResult(
            condition=NetworkCondition.UDP_BLOCKING.value,
            confidence=0.8,
            evidence=["udp_traffic_dropped"],
            severity="medium",
        ),
    )

    return engine
