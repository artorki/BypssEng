import math
import logging
from bypsseng.domain.models import StrategyScore

logger = logging.getLogger("NetAnalyzer")


STRATEGY_CAPABILITIES = {
    "vless": {
        "capabilities": {"udp": False, "tcp": True, "dpi_resistance": 0.5},
        "reliability": 0.7,
        "performance": 0.8,
    },
    "trojan": {
        "capabilities": {"udp": False, "tcp": True, "dpi_resistance": 0.2},
        "reliability": 0.6,
        "performance": 0.7,
    },
    "shadowtls": {
        "capabilities": {"udp": False, "tcp": True, "dpi_resistance": 0.8},
        "reliability": 0.8,
        "performance": 0.6,
    },
    "hysteria2": {
        "capabilities": {"udp": True, "tcp": False, "dpi_resistance": 0.8},
        "reliability": 0.8,
        "performance": 0.9,
    },
    "tuic": {
        "capabilities": {"udp": True, "tcp": False, "dpi_resistance": 0.7},
        "reliability": 0.7,
        "performance": 0.8,
    },
    "tor_proxy": {
        "capabilities": {"udp": False, "tcp": True, "dpi_resistance": 0.9},
        "reliability": 0.8,
        "performance": 0.3,
    },
    "tor_snowflake": {
        "capabilities": {"udp": False, "tcp": True, "dpi_resistance": 1.0},
        "reliability": 0.9,
        "performance": 0.4,
    },
    "warp": {
        "capabilities": {"udp": True, "tcp": False, "dpi_resistance": 0.5},
        "reliability": 0.9,
        "performance": 0.8,
    },
    "naive": {
        "capabilities": {"udp": False, "tcp": True, "dpi_resistance": 0.8},
        "reliability": 0.7,
        "performance": 0.7,
    },
    "cloudflare_worker": {
        "capabilities": {"udp": False, "tcp": True, "dpi_resistance": 0.9},
        "reliability": 0.9,
        "performance": 0.8,
    },
    "psiphon": {
        "capabilities": {"udp": False, "tcp": True, "dpi_resistance": 0.9},
        "reliability": 0.8,
        "performance": 0.6,
    },
    "dnstt": {
        "capabilities": {"udp": False, "tcp": False, "dpi_resistance": 1.0},
        "reliability": 0.6,
        "performance": 0.2,
    },
}


def calculate_health_score(metrics, weights=None):
    if weights is None:
        weights = {"w1": 0.25, "w2": 0.15, "w3": 0.20, "w4": 0.20, "w5": 0.20}
    availability = metrics.get("availability", 0)
    latency = metrics.get("latency", 1000)
    norm_latency = max(0.0, 1.0 - (latency / 1000.0))
    stability = metrics.get("stability", 0)
    throughput = metrics.get("throughput", 0)
    norm_throughput = min(1.0, throughput / 10000.0)
    failure_rate = metrics.get("failure_rate", 1)
    reliability = 1 - failure_rate
    return (
        weights["w1"] * availability
        + weights["w2"] * norm_latency
        + weights["w3"] * stability
        + weights["w4"] * norm_throughput
        + weights["w5"] * reliability
    )


async def score_strategy(strategy_name, states, telemetry_db=None, adaptive_stats=None):
    strategy_data = STRATEGY_CAPABILITIES.get(strategy_name, {})
    caps = strategy_data.get(
        "capabilities", {"udp": True, "tcp": True, "dpi_resistance": 0.0}
    )

    score = 0.0
    reasons = []

    udp_state = states.get("udp", "udp_unknown")
    dpi_state = states.get("dpi", "dpi_none")
    speed_state = states.get("speed", "speed_ok")

    if udp_state == "udp_dropped" and not caps["tcp"]:
        return StrategyScore(
            strategy=strategy_name, score=0.0, reasons=["UDP blocked, TCP unsupported"]
        )

    if dpi_state in ["dpi_aggressive", "dpi_rst"]:
        score += caps["dpi_resistance"] * 0.5
        if caps["dpi_resistance"] > 0.5:
            reasons.append("High DPI resistance")
        else:
            reasons.append("Low DPI resistance")

    if speed_state in ["throttled_intl", "speed_slow"] and caps["udp"]:
        score += 0.3
        reasons.append("UDP protocol good for throttled networks")

    raw_success_rate = 0.0
    if telemetry_db:
        raw_success_rate = await telemetry_db.get_strategy_success_rate(
            strategy_name, dpi_state
        )

    posterior = raw_success_rate
    confidence = 0.5
    if adaptive_stats:
        posterior = await adaptive_stats.get_strategy_posterior(
            strategy_name, dpi_state
        )
        confidence = await adaptive_stats.get_confidence(strategy_name, dpi_state)
    else:

        posterior = (raw_success_rate * 0.8) + (0.5 * 0.2)

    metrics = {
        "availability": posterior,
        "latency": states.get("latency", 500),
        "stability": posterior,
        "throughput": states.get("throughput", 0),
        "failure_rate": 1 - posterior,
    }
    health = calculate_health_score(metrics)

    score += health * (0.4 * confidence)

    if posterior > 0.6:
        reasons.append(
            f"High historical success ({posterior*100:.0f}%) [Conf: {confidence*100:.0f}%]"
        )
    elif posterior > 0.4:
        reasons.append(
            f"Moderate historical success ({posterior*100:.0f}%) [Conf: {confidence*100:.0f}%]"
        )
    else:
        reasons.append("Low historical data/success (Exploration phase)")

    return StrategyScore(strategy=strategy_name, score=score, reasons=reasons)
