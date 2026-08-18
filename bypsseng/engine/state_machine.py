from enum import Enum
from core.logger import log

class EngineState(Enum):
    INIT = "INIT"
    BASELINE = "BASELINE"
    DIAGNOSING = "DIAGNOSING"
    DIAGNOSIS_READY = "DIAGNOSIS_READY"
    SELECTING = "SELECTING"
    STARTING = "STARTING"
    VERIFYING = "VERIFYING"
    ACTIVE = "ACTIVE"
    MONITORING = "MONITORING"
    DEGRADED = "DEGRADED"
    RESELECTING = "RESELECTING"

class StateMachine:
    def __init__(self):
        self.state = EngineState.INIT
        self.transitions = {
            EngineState.INIT: [EngineState.BASELINE],
            EngineState.BASELINE: [EngineState.DIAGNOSING],
            EngineState.DIAGNOSING: [EngineState.DIAGNOSIS_READY],
            EngineState.DIAGNOSIS_READY: [EngineState.SELECTING],
            EngineState.SELECTING: [EngineState.STARTING],
            EngineState.STARTING: [EngineState.VERIFYING],
            EngineState.VERIFYING: [EngineState.ACTIVE, EngineState.DEGRADED], # مسیر ریکاوری اصلاح شد
            EngineState.ACTIVE: [EngineState.MONITORING],
            EngineState.MONITORING: [EngineState.DEGRADED],
            EngineState.DEGRADED: [EngineState.RESELECTING],
            EngineState.RESELECTING: [EngineState.SELECTING],
        }
        
    def transition(self, new_state):
        if new_state in self.transitions.get(self.state, []):
            self.state = new_state
            return True
        log(f"CRITICAL: Invalid state transition from {self.state.value} to {new_state.value}", "ERROR")
        return False
