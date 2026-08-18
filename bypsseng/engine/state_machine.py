# engine/state_machine.py
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
            EngineState.DIAGNOSING: [EngineState.DIAGNOSIS_READY, EngineState.RESELECTING],
            EngineState.DIAGNOSIS_READY: [EngineState.SELECTING],
            EngineState.SELECTING: [EngineState.STARTING, EngineState.RESELECTING],
            EngineState.STARTING: [EngineState.VERIFYING, EngineState.DEGRADED],
            EngineState.VERIFYING: [EngineState.ACTIVE, EngineState.DEGRADED],
            EngineState.ACTIVE: [EngineState.MONITORING],
            EngineState.MONITORING: [EngineState.DEGRADED, EngineState.RESELECTING],
            EngineState.DEGRADED: [EngineState.RESELECTING],
            EngineState.RESELECTING: [EngineState.DIAGNOSING],
        }
        
    def transition(self, new_state):
        if new_state in self.transitions.get(self.state, []):
            self.state = new_state
            return True
        
        err_msg = f"CRITICAL: Invalid state transition from {self.state.value} to {new_state.value}"
        log(err_msg, "ERROR")
        if new_state != EngineState.RESELECTING:
            self.state = EngineState.RESELECTING
            return False
        raise RuntimeError(err_msg)
