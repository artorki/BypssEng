import math
from engine.models import StrategyScore
from telemetry.metrics import get_strategy_success_rate

STRATEGY_CAPABILITIES = {
    "vless": {"udp": False, "tcp": True, "dpi_resistance": 0.5},
    "trojan": {"udp": False, "tcp": True, "dpi_resistance": 0.2},
    "shadowtls": {"udp": False, "tcp": True, "dpi_resistance": 0.8},
    "hysteria2": {"udp": True, "tcp": False, "dpi_resistance": 0.8},
    "tuic": {"udp": True, "tcp": False, "dpi_resistance": 0.7},
    "tor_proxy": {"udp": False, "tcp": True, "dpi_resistance": 0.9},
    "tor_snowflake": {"udp": False, "tcp": True, "dpi_resistance": 1.0},
    "warp": {"udp": True, "tcp": False, "dpi_resistance": 0.5},
    "naive": {"udp": False, "tcp": True, "dpi_resistance": 0.8},
    "cloudflare_worker": {"udp": False, "tcp": True, "dpi_resistance": 0.9},
    "psiphon": {"udp": False, "tcp": True, "dpi_resistance": 0.9},
    "dnstt": {"udp": False, "tcp": False, "dpi_resistance": 1.0},
}

def calculate_health_score(metrics, weights=None):
    if weights is None:
        weights = {'w1': 0.25, 'w2': 0.15, 'w3': 0.20, 'w4': 0.20, 'w5': 0.20}
    
    availability = metrics.get('availability', 0)
    latency = metrics.get('latency', 1000)
    norm_latency = max(0.0, 1.0 - (latency / 1000.0))
    
    stability = metrics.get('stability', 0)
    throughput = metrics.get('throughput', 0)
    norm_throughput = min(1.0, throughput / 10000.0)
    
    failure_rate = metrics.get('failure_rate', 1)
    reliability = 1 - failure_rate
    
    return (
        weights['w1'] * availability +
        weights['w2'] * norm_latency +
        weights['w3'] * stability +
        weights['w4'] * norm_throughput +
        weights['w5'] * reliability
    )

async def score_strategy(strategy_name, states):
    caps = STRATEGY_CAPABILITIES.get(strategy_name, {"udp": True, "tcp": True, "dpi_resistance": 0.0})
    score = 0.0
    reasons = []
    
    udp_state = states.get('udp', 'udp_unknown')
    dpi_state = states.get('dpi', 'dpi_none')
    speed_state = states.get('speed', 'speed_ok')
    
    if udp_state == 'udp_dropped' and not caps["tcp"]:
        return StrategyScore(strategy=strategy_name, score=0.0, reasons=["UDP blocked, TCP unsupported"])
        
    if dpi_state in ['dpi_aggressive', 'dpi_rst']:
        score += caps["dpi_resistance"] * 0.5
        if caps["dpi_resistance"] > 0.5: reasons.append("High DPI resistance")
        else: reasons.append("Low DPI resistance")

    if speed_state in ['throttled_intl', 'speed_slow'] and caps["udp"]:
        score += 0.3
        reasons.append("UDP protocol good for throttled networks")
        
    success_rate = await get_strategy_success_rate(strategy_name, dpi_state)
    
    metrics = {
        'availability': success_rate,
        'latency': states.get('latency', 500),
        'stability': success_rate,
        'throughput': states.get('throughput', 0),
        'failure_rate': 1 - success_rate
    }
    health = calculate_health_score(metrics)
    score += health * 0.4
    
    if success_rate > 0.5: reasons.append(f"High historical success ({success_rate*100:.0f}%)")
    elif success_rate > 0: reasons.append(f"Low historical success ({success_rate*100:.0f}%)")

    return StrategyScore(strategy=strategy_name, score=score, reasons=reasons)
