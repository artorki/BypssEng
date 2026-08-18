# tests/test_state_machine.py
import pytest
from engine.state_machine import StateMachine, EngineState

def test_state_machine_transitions():
    sm = StateMachine()
    assert sm.state == EngineState.INIT
    
    # مسیر صحیح
    assert sm.transition(EngineState.BASELINE) is True
    assert sm.state == EngineState.BASELINE
    
    assert sm.transition(EngineState.DIAGNOSING) is True
    assert sm.transition(EngineState.DIAGNOSIS_READY) is True
    assert sm.transition(EngineState.SELECTING) is True
    assert sm.transition(EngineState.STARTING) is True
    
    # تست مسیر ریکاوری (FAIL -> SELECTING)
    assert sm.transition(EngineState.VERIFYING) is True
    assert sm.transition(EngineState.SELECTING) is True  # برگشت به انتخاب
    
    # تست مسیر موفقیت
    assert sm.transition(EngineState.VERIFYING) is True
    assert sm.transition(EngineState.ACTIVE) is True
    assert sm.transition(EngineState.MONITORING) is True

def test_invalid_transition():
    sm = StateMachine()
    # انتقال غیرمجاز از INIT به ACTIVE
    assert sm.transition(EngineState.ACTIVE) is False
    assert sm.state == EngineState.INIT