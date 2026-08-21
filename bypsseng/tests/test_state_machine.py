


import pytest
from engine.state_machine import StateMachine, EngineState

def test_initial_state():
    """Section 87: lifecycle deterministic."""
    sm = StateMachine()
    assert sm.state == EngineState.INIT

def test_successful_lifecycle():
    """Test the happy path from INIT to MONITORING."""
    sm = StateMachine()
    sm.transition(EngineState.BASELINE)
    sm.transition(EngineState.DIAGNOSING)
    sm.transition(EngineState.DIAGNOSIS_READY)
    sm.transition(EngineState.SELECTING)
    sm.transition(EngineState.STARTING)
    sm.transition(EngineState.VERIFYING)
    sm.transition(EngineState.ACTIVE)
    sm.transition(EngineState.MONITORING)
    assert sm.state == EngineState.MONITORING

def test_degraded_recovery_from_diagnosis():
    """Test recovery path when diagnosis fails."""
    sm = StateMachine()
    sm.transition(EngineState.BASELINE)
    sm.transition(EngineState.DIAGNOSING)

    assert sm.transition(EngineState.RESELECTING) is True
    assert sm.state == EngineState.RESELECTING

    assert sm.transition(EngineState.DIAGNOSING) is True

def test_degraded_recovery_from_starting():
    """Test recovery path when strategy execution fails."""
    sm = StateMachine()
    sm.state = EngineState.STARTING

    assert sm.transition(EngineState.DEGRADED) is True
    assert sm.state == EngineState.DEGRADED

    assert sm.transition(EngineState.RESELECTING) is True

def test_monitoring_failure():
    """Section 34: Monitoring loop failure."""
    sm = StateMachine()
    sm.state = EngineState.MONITORING

    assert sm.transition(EngineState.DEGRADED) is True
    assert sm.state == EngineState.DEGRADED

def test_invalid_transition_forces_degraded():
    """
    Section 35: Invalid transition handling.
    Instead of raising RuntimeError, it should force DEGRADED state.
    """
    sm = StateMachine()

    result = sm.transition(EngineState.ACTIVE)
    assert result is False
    assert sm.state == EngineState.DEGRADED
    

    assert sm.transition(EngineState.RESELECTING) is True
    assert sm.state == EngineState.RESELECTING

def test_invalid_transition_from_degraded():
    """If already DEGRADED, invalid transition should keep it in DEGRADED."""
    sm = StateMachine()
    sm.state = EngineState.DEGRADED

    result = sm.transition(EngineState.ACTIVE)
    assert result is False
    assert sm.state == EngineState.DEGRADED