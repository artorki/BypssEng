from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


@dataclass
class DiagnosisResult:

    condition: str
    confidence: float
    evidence: List[str]
    severity: str


@dataclass
class StrategyScore:

    strategy: str
    score: float
    reasons: List[str]


@dataclass
class DecisionExplanation:

    selected: str
    alternatives: Dict[str, float]
    evidence: List[str]


@dataclass
class Endpoint:

    host: str
    port: int
    protocol: str
    asn: Optional[str] = None
    last_success: Optional[float] = None
    success_rate: float = 0.0
    latency: Optional[float] = None
    stability: float = 0.0
    last_seen: Optional[float] = None
    health_score: float = 0.0


@dataclass
class DecisionContext:

    network_condition: str
    confidence: float
    historical_stats: Dict[str, Any]
    strategy_capabilities: Dict[str, Any]
    endpoint_stats: Optional[Endpoint] = None
    resource_constraints: Dict[str, Any] = field(default_factory=dict)
    temporal_context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Decision:

    selected_strategy: str
    ranked_candidates: List[StrategyScore]
    confidence: float
    expected_score: float
    reasons: List[str]
    fallback_plan: List[str] = field(default_factory=list)
