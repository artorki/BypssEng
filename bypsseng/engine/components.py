import time
import hashlib

def calculate_health_score(metrics, weights=None):
    if weights is None:
        weights = {'w1': 0.25, 'w2': 0.15, 'w3': 0.20, 'w4': 0.20, 'w5': 0.20}
    availability = metrics.get('availability', 0)
    latency = metrics.get('latency', 0)
    stability = metrics.get('stability', 0)
    throughput = metrics.get('throughput', 0)
    failure_rate = metrics.get('failure_rate', 1)
    reliability = 1 - failure_rate
    return (
        weights['w1'] * availability +
        weights['w2'] * latency +
        weights['w3'] * stability +
        weights['w4'] * throughput +
        weights['w5'] * reliability
    )

class BenchmarkFramework:
    @staticmethod
    async def run_benchmark(strategy_name, test_func):
        start = time.time()
        success = await test_func()
        latency = (time.time() - start) * 1000
        return {"strategy": strategy_name, "success": success, "latency": latency}

class FailureInjector:
    @staticmethod
    def get_scenario(name):
        scenarios = {
            "dns_failure": {"dns": "fail"},
            "high_latency": {"latency": "high"},
            "packet_loss": {"packet_loss": "high"}
        }
        return scenarios.get(name)

class SupplyChainManager:
    @staticmethod
    async def verify_hash(file_path, expected_hash):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest() == expected_hash
