from engine.models import DiagnosisResult

class RuleEngine:
    def __init__(self):
        self.rules = []
        
    def add_rule(self, condition, action):
        self.rules.append((condition, action))
        
    def evaluate(self, context):
        diagnoses = []
        for condition, action in self.rules:
            if condition(context):
                diagnoses.append(action(context))
        
        if not diagnoses:
            return [DiagnosisResult(condition="undetermined", confidence=0.5, evidence=[], severity="low")]
        return diagnoses
