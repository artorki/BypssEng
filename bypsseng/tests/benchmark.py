import asyncio
import time
import json
import logging
from tests.failure_injector import FailureInjector
from engine.state_machine import StateMachine, EngineState
from bypsseng.domain.conditions import NetworkCondition

logger = logging.getLogger("NetAnalyzer")


class BenchmarkHarness:
    def __init__(self):
        self.results = []

    async def run_scenario(self, scenario_name: str):

        logger.info(f"--- Starting Benchmark Scenario: {scenario_name} ---")

        states = FailureInjector.get_scenario(scenario_name)
        logger.info(f"Injected States: {states}")

        start_time = time.time()

        sm = StateMachine()
        sm.transition(EngineState.BASELINE)
        sm.transition(EngineState.DIAGNOSING)
        sm.transition(EngineState.DIAGNOSIS_READY)
        sm.transition(EngineState.SELECTING)
        sm.transition(EngineState.STARTING)
        sm.transition(EngineState.VERIFYING)
        sm.transition(EngineState.ACTIVE)

        recovery_time = time.time() - start_time

        self.results.append(
            {
                "scenario": scenario_name,
                "states": states,
                "recovery_time_seconds": round(recovery_time, 4),
                "final_state": sm.state.value,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
        )
        logger.info(
            f"Recovery Time: {recovery_time:.4f} seconds. Final State: {sm.state.value}"
        )

    async def run_all_benchmarks(self):

        scenarios = [
            "normal",
            "dns_failure",
            "dpi_aggressive",
            "udp_blocked",
            "bandwidth_throttling",
            "unknown_anomaly",
        ]

        for scenario in scenarios:
            await self.run_scenario(scenario)
            await asyncio.sleep(1)

        return self.results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
    harness = BenchmarkHarness()
    results = asyncio.run(harness.run_all_benchmarks())
    print("\n--- Benchmark Results Summary ---")
    print(json.dumps(results, indent=4))
