from engine.rule_engine import RuleEngine
from engine.models import DiagnosisResult

def setup_decision_rules():
    engine = RuleEngine()
    
    engine.add_rule(
        lambda s: s.get('captive', False) == True,
        lambda s: DiagnosisResult(condition="captive_portal", confidence=1.0, evidence=["captive_portal_detected"], severity="high")
    )
    engine.add_rule(
        lambda s: s.get('dns') in ['dns_dropped', 'dns_hijacked'],
        lambda s: DiagnosisResult(condition="dns_interference", confidence=0.9, evidence=["dns_disruption_detected"], severity="high")
    )
    engine.add_rule(
        lambda s: s.get('dpi') in ['dpi_aggressive', 'dpi_rst'],
        lambda s: DiagnosisResult(condition="dpi_filtering", confidence=0.85, evidence=["sni_filtering_detected"], severity="high")
    )
    engine.add_rule(
        lambda s: s.get('speed') in ['throttled_intl', 'speed_slow'],
        lambda s: DiagnosisResult(condition="bandwidth_throttling", confidence=0.75, evidence=["international_speed_low"], severity="medium")
    )
    engine.add_rule(
        lambda s: s.get('udp') == 'udp_dropped',
        lambda s: DiagnosisResult(condition="udp_blocking", confidence=0.8, evidence=["udp_traffic_dropped"], severity="medium")
    )
    
    return engine
