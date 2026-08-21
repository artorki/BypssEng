


from bypsseng.domain.models import DiagnosisResult
from bypsseng.domain.conditions import NetworkCondition
import logging
from typing import Callable, List, Dict, Any

logger = logging.getLogger("NetAnalyzer")

class RuleEngine:
    """
    Evaluates network states against a set of rules.
    Section 8: Hybrid architecture (Rules + Scoring).
    Section 27: Returns INSUFFICIENT_DATA if no rules match (Unknown Anomaly).
    """
    def __init__(self):
        self.rules: List[tuple] = []
        
    def add_rule(self, condition: Callable[[Dict[str, Any]], bool], action: Callable):
        """Adds a rule to the engine."""
        self.rules.append((condition, action))
        
    def evaluate(self, context: Dict[str, Any]) -> List[DiagnosisResult]:
        """Evaluates the context against all rules."""
        diagnoses = []
        for condition, action in self.rules:
            try:
                if condition(context):
                    diagnoses.append(action(context))
            except Exception as e:
                logger.error(f"Error evaluating rule: {e}", exc_info=True)
            
        if not diagnoses:

            logger.warning("No rules matched the current network state. Returning INSUFFICIENT_DATA.")
            return [DiagnosisResult(
                condition=NetworkCondition.SPEED_FAILED.value, # SPEED_FAILED maps to INSUFFICIENT_DATA in classification
                confidence=0.5, 
                evidence=["no_matching_rules", "undetermined_state"], 
                severity="low"
            )]
        return diagnoses