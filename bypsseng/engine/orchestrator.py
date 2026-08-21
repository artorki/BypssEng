


import asyncio
import random
import logging
from engine.state_machine import StateMachine, EngineState
from decision.policies import setup_decision_rules
from bypsseng.domain.models import DiagnosisResult, DecisionExplanation
from core.logger import log
from config.models import CONFIG

from diagnosis.health import check_direct_health, check_geolocation, check_captive_portal
from diagnosis.connectivity import test_ip_layer
from diagnosis.dns import test_dns_layer
from diagnosis.tls import test_dpi_layer
from diagnosis.bandwidth import test_throttling
from diagnosis.transport import test_udp_status
from runtime.process import pm

logger = logging.getLogger("NetAnalyzer")

class Orchestrator:
    """
    Heart of the control lifecycle (HANDOFF Sec 2, 16).
    Orchestrator owns State. RuntimeManager owns OS Process. Strategy owns definition.
    """
    def __init__(self, app_dir, bypass_executor, telemetry_db, runtime_session=None, net_manager=None, report_callback=None, progress_callback=None, diagnose_only=False):
        self.app_dir = app_dir
        self.bypass_executor = bypass_executor
        self.telemetry_db = telemetry_db
        self.runtime_session = runtime_session
        self.net_manager = net_manager
        self.sm = StateMachine()
        self.rule_engine = setup_decision_rules()
        self.report_callback = report_callback
        self.progress_callback = progress_callback
        self.states = {}
        self.diagnose_only = diagnose_only # Section 54
        

        self.local_http_port = runtime_session.local_http_port if runtime_session else 10809

    async def run(self):
        """Main state machine loop with robust recovery (Section 35)."""

        if self.report_callback:
            self.report_callback({}, "starting", [], "starting")
            
        self.sm.transition(EngineState.BASELINE)
        while True:
            try:
                current_state = self.sm.state
                
                if current_state in [EngineState.BASELINE, EngineState.RESELECTING]:
                    await self.diagnose()
                    
                elif current_state == EngineState.DIAGNOSIS_READY:
                    await self.select_and_connect()
                    
                elif current_state == EngineState.STARTING:
                    await asyncio.sleep(1) 
                    
                elif current_state == EngineState.VERIFYING:
                    await self.verify()
                    
                elif current_state == EngineState.ACTIVE:
                    self.sm.transition(EngineState.MONITORING)
                    



                elif current_state == EngineState.MONITORING:
                    if await pm.test_current_proxy_health(self.local_http_port):
                        log("Network stable in monitoring cycle. Sleeping...", "INFO")
                        await asyncio.sleep(CONFIG.intervals.test_loop + random.uniform(0, 15))
                    else:
                        log("Health check failed during monitoring. Entering DEGRADED state.", "WARN")
                        self.sm.transition(EngineState.DEGRADED)
                        
                elif current_state == EngineState.DEGRADED:
                    log("Connection degraded. Triggering re-diagnosis...", "WARN")
                    self.sm.transition(EngineState.RESELECTING)
                    await asyncio.sleep(5)
                    
                else:
                    log(f"Unknown state {current_state}. Resetting to RESELECTING.", "WARN")
                    self.sm.transition(EngineState.RESELECTING)
                    
            except asyncio.CancelledError:
                raise
            except Exception as e:



                logger.error(f"Orchestrator error: {e}", exc_info=True)
                log(f"Orchestrator error: {e}. Forcing DEGRADED state for recovery.", "ERROR")
                self.sm.state = EngineState.DEGRADED
                await asyncio.sleep(5)

    async def diagnose(self):
        """Runs the 5-phase diagnosis pipeline."""
        log("==================================================", "HEADER")
        self.sm.transition(EngineState.DIAGNOSING)
        
        if self.progress_callback: await self.progress_callback({"phase": "start", "status": "running"})
        
        if not await check_geolocation():
            await asyncio.sleep(CONFIG.intervals.test_loop + random.uniform(0, 15))
            self.sm.transition(EngineState.RESELECTING)
            return

        if await check_captive_portal():
            log("CRITICAL: Captive Portal detected! Please authenticate in your browser.", "FAIL")
            self.states = {'captive': True}
            log("Halting diagnosis for 2 minutes...", "WARN")
            await asyncio.sleep(120)
            self.sm.transition(EngineState.RESELECTING)
            return

        if await check_direct_health():
            log("Network is healthy (Direct access succeeded). No bypass needed.", "PASS")
            self.states = {'ip': {'internal': True, 'external': True}, 'dns': 'dns_ok', 'dpi': 'dpi_none', 'speed': 'speed_ok'}
            
            if self.report_callback:
                self.report_callback(self.states, "healthy", ["direct_access_ok"], "healthy")
                




                
            log(f"Waiting for {CONFIG.intervals.test_loop} seconds before next diagnosis cycle...", "INFO")
            await asyncio.sleep(CONFIG.intervals.test_loop + random.uniform(0, 15))
            self.sm.transition(EngineState.RESELECTING)
            return


        if self.progress_callback: await self.progress_callback({"phase": 1, "name": "Network & Routing", "status": "running"})
        ip_s = await test_ip_layer()
        if self.progress_callback: await self.progress_callback({"phase": 1, "status": "done", "data": ip_s})
        

        if self.progress_callback: await self.progress_callback({"phase": 2, "name": "DNS Layer", "status": "running"})
        dns_res = await test_dns_layer()
        if self.progress_callback: await self.progress_callback({"phase": 2, "status": "done", "data": dns_res.condition})
        

        if self.progress_callback: await self.progress_callback({"phase": 4, "name": "DPI Inspection", "status": "running"})
        try:
            from diagnosis.dpi_kernel import test_kernel_dpi
            kernel_dpi = await test_kernel_dpi()
            dpi_res = kernel_dpi if kernel_dpi else await test_dpi_layer()
        except ImportError:
            dpi_res = await test_dpi_layer()
        if self.progress_callback: await self.progress_callback({"phase": 4, "status": "done", "data": dpi_res.condition})
        

        if self.progress_callback: await self.progress_callback({"phase": 5, "name": "Bandwidth", "status": "running"})
        speed_res = await test_throttling()
        if self.progress_callback: await self.progress_callback({"phase": 5, "status": "done", "data": speed_res.condition})
        

        if self.progress_callback: await self.progress_callback({"phase": 3, "name": "UDP Status", "status": "running"})
        udp_res = await test_udp_status()
        if self.progress_callback: await self.progress_callback({"phase": 3, "status": "done", "data": udp_res.condition})

        self.states = {
            'ip': ip_s, 'dns': dns_res.condition, 'dpi': dpi_res.condition, 
            'speed': speed_res.condition, 'udp': udp_res.condition
        }
        log(f"Diagnosis completed: {self.states}", "INFO")
        
        if self.progress_callback: await self.progress_callback({"phase": "final", "status": "done", "states": self.states})
        
        self.sm.transition(EngineState.DIAGNOSIS_READY)

    async def select_and_connect(self):
        """Evaluates rules and executes bypass strategy."""
        self.sm.transition(EngineState.SELECTING)
        diagnoses = self.rule_engine.evaluate(self.states)
        primary_diagnosis = max(diagnoses, key=lambda d: d.confidence)
        

        log(f"Decision Engine Result: {primary_diagnosis.condition} (Confidence: {primary_diagnosis.confidence})", "SOL")

        self.sm.transition(EngineState.STARTING)
        
        success, explanation = await self.bypass_executor(self.states, primary_diagnosis)
        
        if explanation:
            log(f"Decision Explainability: Selected {explanation.selected} over {explanation.alternatives}. Reasons: {explanation.evidence}", "INFO")
            

            if self.telemetry_db:
                await self.telemetry_db.insert_decision_telemetry(
                    diagnosis=primary_diagnosis.condition, confidence=primary_diagnosis.confidence,
                    selected_strategy=explanation.selected, score=0.0, result="success" if success else "failed",
                    explanation={"alternatives": explanation.alternatives, "reasons": explanation.evidence}
                )

        if success:
            self.sm.transition(EngineState.VERIFYING)
        else:
            log("Bypass execution failed. Retrying selection...", "WARN")
            if self.telemetry_db:
                await self.telemetry_db.record_strategy_outcome("all_failed", primary_diagnosis.condition, False)
            if self.report_callback:
                self.report_callback(self.states, "failed", [primary_diagnosis.condition], "failed")
            self.sm.transition(EngineState.DEGRADED)

    async def verify(self):
        """Verifies if the proxy is actually working."""
        log("Verifying connection...", "INFO")
        if await pm.test_current_proxy_health(self.local_http_port):
            log("Verification successful. Entering ACTIVE state.", "PASS")
            self.sm.transition(EngineState.ACTIVE)
        else:
            log("Verification failed. Entering DEGRADED state.", "WARN")
            self.sm.transition(EngineState.DEGRADED)