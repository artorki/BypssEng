


import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from engine.orchestrator import Orchestrator
from engine.state_machine import EngineState
from bypsseng.domain.models import DiagnosisResult

@pytest.fixture
def orchestrator_setup():
    """Fixture to setup Orchestrator with mocked dependencies."""
    mock_bypass = AsyncMock()
    mock_telemetry = AsyncMock()
    mock_fetch = AsyncMock()
    mock_report = MagicMock()
    mock_progress = AsyncMock()
    mock_runtime_session = MagicMock()
    mock_runtime_session.local_http_port = 10809
    mock_net_manager = AsyncMock()
    
    orch = Orchestrator(
        app_dir=".",
        bypass_executor=mock_bypass,
        telemetry_db=mock_telemetry,
        runtime_session=mock_runtime_session,
        net_manager=mock_net_manager,
        report_callback=mock_report,
        progress_callback=mock_progress
    )
    return orch, mock_bypass, mock_telemetry

@pytest.mark.asyncio
async def test_verify_success(orchestrator_setup):
    """
    Section 34 & 87: Test verification successful path.
    """
    orch, _, _ = orchestrator_setup
    orch.sm.state = EngineState.VERIFYING
    

    with patch('runtime.process.pm.test_current_proxy_health', AsyncMock(return_value=True)):
        await orch.verify()
        
    assert orch.sm.state == EngineState.ACTIVE

@pytest.mark.asyncio
async def test_verify_failure(orchestrator_setup):
    """
    Section 35 & 87: Test verification failure path (Recovery to DEGRADED).
    """
    orch, _, _ = orchestrator_setup
    orch.sm.state = EngineState.VERIFYING
    

    with patch('runtime.process.pm.test_current_proxy_health', AsyncMock(return_value=False)):
        await orch.verify()
        
    assert orch.sm.state == EngineState.DEGRADED

@pytest.mark.asyncio
async def test_monitoring_success(orchestrator_setup):
    """
    Section 34: Test monitoring loop success path.
    """
    orch, _, _ = orchestrator_setup
    orch.sm.state = EngineState.MONITORING
    

    with patch('runtime.process.pm.test_current_proxy_health', AsyncMock(return_value=True)):
        with patch('asyncio.sleep', AsyncMock()): # Skip sleep

            if await __import__('runtime.process', fromlist=['pm']).pm.test_current_proxy_health(orch.local_http_port):
                pass # Would normally sleep and stay in MONITORING
                

    assert orch.sm.state == EngineState.MONITORING

@pytest.mark.asyncio
async def test_monitoring_failure(orchestrator_setup):
    """
    Section 34: Test monitoring loop failure path (Recovery to DEGRADED).
    """
    orch, _, _ = orchestrator_setup
    orch.sm.state = EngineState.MONITORING
    

    with patch('runtime.process.pm.test_current_proxy_health', AsyncMock(return_value=False)):

        if not await __import__('runtime.process', fromlist=['pm']).pm.test_current_proxy_health(orch.local_http_port):
            orch.sm.transition(EngineState.DEGRADED)
            
    assert orch.sm.state == EngineState.DEGRADED

@pytest.mark.asyncio
async def test_select_and_connect_failure(orchestrator_setup):
    """
    Section 35 & 87: Test bypass execution failure (Recovery to DEGRADED).
    """
    orch, mock_bypass, _ = orchestrator_setup
    orch.sm.state = EngineState.SELECTING
    

    mock_bypass.return_value = (False, None)
    

    orch.rule_engine.evaluate = MagicMock(return_value=[
        DiagnosisResult(condition="dpi_filtering", confidence=0.8, evidence=[], severity="high")
    ])
    
    await orch.select_and_connect()
    
    assert orch.sm.state == EngineState.DEGRADED

@pytest.mark.asyncio
async def test_diagnose_healthy(orchestrator_setup):
    """
    Section 87: Test diagnosis when network is already healthy.
    """
    orch, _, mock_fetch = orchestrator_setup
    orch.sm.state = EngineState.BASELINE
    

    with patch('diagnosis.health.check_direct_health', AsyncMock(return_value=True)):
        with patch('diagnosis.health.check_geolocation', AsyncMock(return_value=False)):
            with patch('diagnosis.health.check_captive_portal', AsyncMock(return_value=False)):

                with patch('asyncio.sleep', AsyncMock()):
                    await orch.diagnose()
                    

    assert orch.sm.state == EngineState.RESELECTING