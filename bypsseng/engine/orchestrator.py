import asyncio
import random
from engine.state_machine import StateMachine, EngineState
from decision.policies import setup_decision_rules
from engine.models import DiagnosisResult
from core.logger import log
from config.models import CONFIG

from diagnosis.health import check_direct_health, check_geolocation, check_captive_portal
from diagnosis.connectivity import test_ip_layer
from diagnosis.dns import test_dns_layer
from diagnosis.tls import test_dpi_layer
from diagnosis.bandwidth import test_throttling
from diagnosis.transport import test_udp_status

import telemetry.storage as telemetry

class Orchestrator:
    def __init__(self, app_dir, bypass_executor):
        self.app_dir = app_dir
        self.sm = StateMachine()
        self.rule_engine = setup_decision_rules()
        self.bypass_executor = bypass_executor
        self.states = {}

    async def run(self):
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
                elif self.sm.state == EngineState.DEGRADED:
                    log("Connection degraded. Triggering reselection...", "WARN")
                    self.sm.transition(EngineState.RESELECTING)
                    await asyncio.sleep(5)
                else:
                    log(f"Unknown state {self.sm.state}. Resetting to BASELINE.", "WARN")
                    self.sm.transition(EngineState.RESELECTING)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log(f"Orchestrator error: {e}", "ERROR")
                self.sm.transition(EngineState.RESELECTING)
                await asyncio.sleep(10)

    async def diagnose(self):
        log("==================================================", "HEADER")
        self.sm.transition(EngineState.DIAGNOSING)
        
        if not await check_geolocation():
            await asyncio.sleep(CONFIG.intervals.test_loop + random.uniform(0, 15))
            self.sm.transition(EngineState.BASELINE)
            return

        if await check_captive_portal():
            log("Captive Portal detected! Network tests may be misleading.", "WARN")
            self.states = {'dpi': 'dpi_unknown', 'captive': True}

        if await check_direct_health():
            self.states = {'ip': {'internal': True, 'external': True}, 'dns': 'dns_ok', 'dpi': 'dpi_none', 'speed': 'speed_ok'}
            self.sm.transition(EngineState.DIAGNOSIS_READY)
            return

        ip_s = await test_ip_layer()
        dns_res = await test_dns_layer()
        dpi_res = await test_dpi_layer()
        speed_res = await test_throttling()
        udp_res = await test_udp_status()
        
        self.states = {
            'ip': ip_s, 'dns': dns_res.condition, 'dpi': dpi_res.condition, 
            'speed': speed_res.condition, 'udp': udp_res.condition
        }
        log(f"Diagnosis completed: {self.states}", "INFO")
        self.sm.transition(EngineState.DIAGNOSIS_READY)

    async def select_and_connect(self):
        self.sm.transition(EngineState.SELECTING)
        diagnosis_result = self.rule_engine.evaluate(self.states)
        if not diagnosis_result:
            diagnosis_result = DiagnosisResult(condition="undetermined", confidence=0.5, evidence=[], severity="low")

        log(f"Decision Engine Result: {diagnosis_result.condition} (Confidence: {diagnosis_result.confidence})", "SOL")

        self.sm.transition(EngineState.STARTING)
        
        success = await self.bypass_executor(self.states, diagnosis_result)
        
        if success:
            self.sm.transition(EngineState.VERIFYING)
        else:
            log("Bypass execution failed. Retrying selection...", "WARN")
            await telemetry.record_strategy_outcome("all_failed", diagnosis_result.condition, False)
            self.sm.transition(EngineState.RESELECTING)
            await asyncio.sleep(CONFIG.intervals.test_loop)

    async def verify(self):
        log("Verifying connection...", "INFO")
        from BypssEng import test_current_proxy_health
        if await test_current_proxy_health():
            log("Verification successful. Entering ACTIVE state.", "PASS")
            self.sm.transition(EngineState.ACTIVE)
        else:
            log("Verification failed. Entering DEGRADED state.", "WARN")
            self.sm.transition(EngineState.DEGRADED)

    async def monitor(self):
        self.sm.transition(EngineState.MONITORING)
        log("Monitoring network health...", "INFO")
        from BypssEng import test_current_proxy_health
        if await test_current_proxy_health():
            await asyncio.sleep(CONFIG.intervals.test_loop + random.uniform(0, 15))
        else:
            self.sm.transition(EngineState.DEGRADED)
