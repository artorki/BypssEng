from bypsseng.domain.models import DiagnosisResult
from bypsseng.domain.conditions import NetworkCondition
import logging
from typing import Callable, List, Dict, Any

logger = logging.getLogger("NetAnalyzer")


class RuleEngine:

    def __init__(self):
        self.rules: List[tuple] = []

    def add_rule(self, condition: Callable[[Dict[str, Any]], bool], action: Callable):

        self.rules.append((condition, action))

    def evaluate(self, context: Dict[str, Any]) -> List[DiagnosisResult]:

        diagnoses = []
        for condition, action in self.rules:
            try:
                if condition(context):
                    diagnoses.append(action(context))
            except Exception as e:
                logger.error(f"Error evaluating rule: {e}", exc_info=True)

        if not diagnoses:

            logger.warning(
                "No rules matched the current network state. Returning INSUFFICIENT_DATA."
            )
            return [
                DiagnosisResult(
                    condition=NetworkCondition.SPEED_FAILED.value,
                    confidence=0.5,
                    evidence=["no_matching_rules", "undetermined_state"],
                    severity="low",
                )
            ]
        return diagnoses
