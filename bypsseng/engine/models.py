from dataclasses import dataclass

@dataclass
class TimeoutConfig:
    dns: float
    tcp: float
    http: float

@dataclass
class DiagnosisResult:
    condition: str
    confidence: float
    evidence: list
    severity: str

@dataclass
class StrategyScore:
    strategy: str
    score: float
    reasons: list

@dataclass
class DecisionExplanation:
    selected: str
    alternatives: dict
    evidence: list
