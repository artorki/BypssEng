# decision/scorer.py
from engine.models import StrategyScore
from telemetry.metrics import get_strategy_success_rate

def calculate_health_score(metrics, weights=None):
    if weights is None:
        weights = {'w1': 0.25, 'w2': 0.15, 'w3': 0.20, 'w4': 0.20, 'w5': 0.20}
    availability = metrics.get('availability', 0)
    latency = metrics.get('latency', 0)
    stability = metrics.get('stability', 0)
    throughput = metrics.get('throughput', 0)
    failure_rate = metrics.get('failure_rate', 1)
    reliability = 1 - failure_rate
    return (
        weights['w1'] * availability + weights['w2'] * latency +
        weights['w3'] * stability + weights['w4'] * throughput +
        weights['w5'] * reliability
    )

async def score_strategy(strategy_name, states):
    score = 0.0
    reasons = []
    
    # استخراج شرایط شبکه
    udp_state = states.get('udp', 'udp_unknown')
    dpi_state = states.get('dpi', 'dpi_none')
    speed_state = states.get('speed', 'speed_ok')
    
    # قوانین امتیازدهی
    if udp_state == 'udp_dropped' and strategy_name in ["hysteria2", "tuic", "warp"]:
        return StrategyScore(strategy=strategy_name, score=0.0, reasons=["UDP blocked"])
    
    if dpi_state in ['dpi_aggressive', 'dpi_rst']:
        if strategy_name in ["vless_reality", "shadowtls", "naive"]:
            score += 0.5
            reasons.append("Resistant to DPI")
        else:
            score -= 0.3
            reasons.append("Vulnerable to DPI")

    if speed_state in ['throttled_intl', 'speed_slow'] and strategy_name in ["hysteria2", "tuic"]:
        score += 0.3
        reasons.append("Good for throttled networks")
        
    # بررسی تاریخچه موفقیت استراتژی (Historical Data)
    success_rate = await get_strategy_success_rate(strategy_name, dpi_state)
    score += success_rate * 0.4
    if success_rate > 0.5:
        reasons.append(f"High historical success ({success_rate*100:.0f}%)")
    elif success_rate > 0:
        reasons.append(f"Low historical success ({success_rate*100:.0f}%)")

    return StrategyScore(strategy=strategy_name, score=score, reasons=reasons)
