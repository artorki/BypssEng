import time
import asyncio
from core.logger import log
from telemetry.storage import record_strategy_outcome

class BenchmarkFramework:
    @staticmethod
    async def run_benchmark(strategy_name, test_func, condition="normal"):
        log(f"Starting benchmark for {strategy_name} under {condition}...", "SOL")
        start = time.time()
        try:
            success = await test_func()
            latency = (time.time() - start) * 1000
            
            await record_strategy_outcome(strategy_name, condition, success)
            
            log(f"Benchmark {strategy_name}: Success={success}, Latency={latency:.2f}ms", "PASS")
            return {"strategy": strategy_name, "success": success, "latency": latency}
        except Exception as e:
            log(f"Benchmark failed for {strategy_name}: {e}", "ERROR")
            await record_strategy_outcome(strategy_name, condition, False)
            return {"strategy": strategy_name, "success": False, "latency": 0}
