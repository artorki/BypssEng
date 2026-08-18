import asyncio
import random
from engine.state_machine import StateMachine, EngineState
from decision.policies import setup_decision_rules
from engine.models import DiagnosisResult, DecisionExplanation
from core.logger import log
from config.models import CONFIG

from diagnosis.health import check_direct_health, check_geolocation, check_captive_portal
from diagnosis.connectivity import test_ip_layer
from diagnosis.dns import test_dns_layer
from diagnosis.tls import test_dpi_layer
from diagnosis.bandwidth import test_throttling
from diagnosis.transport import test_udp_status
from runtime.process import pm

import telemetry.storage as telemetry

class Orchestrator:
    def __init__(self, app_dir, bypass_executor, local_http_port, fetch_config_callback=None, report_callback=None, progress_callback=None):
        self.app_dir = app_dir
        self.local_http_port = local_http_port
        self.sm = StateMachine()
        self.rule_engine = setup_decision_rules()
        self.bypass_executor = bypass_executor
        self.fetch_config_callback = fetch_config_callback
        self.report_callback = report_callback
        self.progress_callback = progress_callback
        self.states = {}

    async def run(self):
        if self.report_callback:
            self.report_callback({}, "starting", [], "starting")
            
        self.sm.transition(EngineState.BASELINE)
        while True:
            try:
                if self.sm.state in [EngineState.BASELINE, EngineState.RESELECTING]:
                    await self.diagnose()
                elif self.sm.state == EngineState.DIAGNOSIS_READY:
                    await self.select_and_connect()
                elif self.sm.state == EngineState.STARTING:
                    await asyncio.sleep(1) 
                elif self.sm.state == EngineState.VERIFYING:
                    await self.verify()
                elif self.sm.state == EngineState.ACTIVE:
                    await self.monitor()
                elif self.sm.state == EngineState.MONITORING:
                    await asyncio.sleep(1)
                elif self.sm.state == EngineState.DEGRADED:
                    log("Connection degraded. Triggering re-diagnosis...", "WARN")
                    self.sm.transition(EngineState.RESELECTING)
                    await asyncio.sleep(5)
                else:
                    log(f"Unknown state {self.sm.state}. Resetting to RESELECTING.", "WARN")
                    self.sm.transition(EngineState.RESELECTING)
                    
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log(f"Orchestrator error: {e}", "ERROR")
                self.sm.state = EngineState.DEGRADED
                await asyncio.sleep(5)

    async def diagnose(self):
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
                
            if self.fetch_config_callback:
                log("Network is healthy. Fetching fresh configs in background...", "INFO")
                asyncio.create_task(self.fetch_config_callback(wait=False))
                
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
        from diagnosis.dpi_kernel import test_kernel_dpi
        kernel_dpi = await test_kernel_dpi()
        if kernel_dpi:
            dpi_res = kernel_dpi
        else:
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
        self.sm.transition(EngineState.SELECTING)
        diagnoses = self.rule_engine.evaluate(self.states)
        primary_diagnosis = max(diagnoses, key=lambda d: d.confidence)
        
        log(f"Decision Engine Result: {primary_diagnosis.condition} (Confidence: {primary_diagnosis.confidence})", "SOL")

        self.sm.transition(EngineState.STARTING)
        
        success, explanation = await self.bypass_executor(self.states, primary_diagnosis)
        
        if explanation:
            log(f"Decision Explainability: Selected {explanation.selected} over {explanation.alternatives}. Reasons: {explanation.evidence}", "INFO")
            await telemetry.insert_decision_telemetry(
                diagnosis=primary_diagnosis.condition, confidence=primary_diagnosis.confidence,
                selected_strategy=explanation.selected, score=0.0, result="success" if success else "failed",
                explanation={"alternatives": explanation.alternatives, "reasons": explanation.evidence}
            )

        if success:
            self.sm.transition(EngineState.VERIFYING)
        else:
            log("Bypass execution failed. Retrying selection...", "WARN")
            await telemetry.record_strategy_outcome("all_failed", primary_diagnosis.condition, False)
            if self.report_callback:
                self.report_callback(self.states, "failed", [primary_diagnosis.condition], "failed")
            self.sm.transition(EngineState.DEGRADED)

    async def verify(self):
        log("Verifying connection...", "INFO")
        if await pm.test_current_proxy_health(self.local_http_port):
            log("Verification successful. Entering ACTIVE state.", "PASS")
            self.sm.transition(EngineState.ACTIVE)
        else:
            log("Verification failed. Entering DEGRADED state.", "WARN")
            self.sm.transition(EngineState.DEGRADED)

    async def monitor(self):
        self.sm.transition(EngineState.MONITORING)
        log("Monitoring network health...", "INFO")
        if await pm.test_current_proxy_health(self.local_http_port):
            await asyncio.sleep(CONFIG.intervals.test_loop + random.uniform(0, 15))
            self.sm.state = EngineState.MONITORING 
        else:
            self.sm.transition(EngineState.DEGRADED)
