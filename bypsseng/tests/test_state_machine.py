import pytest
from engine.state_machine import StateMachine, EngineState


def test_initial_state():

    sm = StateMachine()
    assert sm.state == EngineState.INIT


def test_successful_lifecycle():

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

    sm = StateMachine()
    sm.transition(EngineState.BASELINE)
    sm.transition(EngineState.DIAGNOSING)

    assert sm.transition(EngineState.RESELECTING) is True
    assert sm.state == EngineState.RESELECTING

    assert sm.transition(EngineState.DIAGNOSING) is True


def test_degraded_recovery_from_starting():

    sm = StateMachine()
    sm.state = EngineState.STARTING

    assert sm.transition(EngineState.DEGRADED) is True
    assert sm.state == EngineState.DEGRADED

    assert sm.transition(EngineState.RESELECTING) is True


def test_monitoring_failure():

    sm = StateMachine()
    sm.state = EngineState.MONITORING

    assert sm.transition(EngineState.DEGRADED) is True
    assert sm.state == EngineState.DEGRADED


def test_invalid_transition_forces_degraded():

    sm = StateMachine()

    result = sm.transition(EngineState.ACTIVE)
    assert result is False
    assert sm.state == EngineState.DEGRADED

    assert sm.transition(EngineState.RESELECTING) is True
    assert sm.state == EngineState.RESELECTING


def test_invalid_transition_from_degraded():

    sm = StateMachine()
    sm.state = EngineState.DEGRADED

    result = sm.transition(EngineState.ACTIVE)
    assert result is False
    assert sm.state == EngineState.DEGRADED
