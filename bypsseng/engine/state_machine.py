from enum import Enum
import logging

logger = logging.getLogger("NetAnalyzer")


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
            EngineState.BASELINE: [EngineState.DIAGNOSING, EngineState.RESELECTING],
            EngineState.DIAGNOSING: [
                EngineState.DIAGNOSIS_READY,
                EngineState.RESELECTING,
            ],
            EngineState.DIAGNOSIS_READY: [
                EngineState.SELECTING,
                EngineState.RESELECTING,
            ],
            EngineState.SELECTING: [EngineState.STARTING, EngineState.RESELECTING],
            EngineState.STARTING: [EngineState.VERIFYING, EngineState.DEGRADED],
            EngineState.VERIFYING: [EngineState.ACTIVE, EngineState.DEGRADED],
            EngineState.ACTIVE: [EngineState.MONITORING, EngineState.DEGRADED],
            EngineState.MONITORING: [EngineState.DEGRADED, EngineState.RESELECTING],
            EngineState.DEGRADED: [EngineState.RESELECTING],
            EngineState.RESELECTING: [EngineState.DIAGNOSING],
        }

    def transition(self, new_state):

        if new_state in self.transitions.get(self.state, []):

            logger.debug(f"State transition: {self.state.value} -> {new_state.value}")
            self.state = new_state
            return True

        err_msg = f"Invalid state transition from {self.state.value} to {new_state.value}. Forcing DEGRADED."
        logger.error(err_msg)

        if self.state != EngineState.DEGRADED:
            self.state = EngineState.DEGRADED

        return False
