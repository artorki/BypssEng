# tests/failure_injector.py
class FailureInjector:

    @staticmethod
    def get_scenario(name):
        scenarios = {
            "dns_failure": {"dns": "dns_dropped", "udp": "udp_ok", "dpi": "dpi_none"},
            "dpi_aggressive": {"dns": "dns_ok", "udp": "udp_ok", "dpi": "dpi_aggressive"},
            "udp_blocked": {"dns": "dns_ok", "udp": "udp_dropped", "dpi": "dpi_none"},
            "normal": {"dns": "dns_ok", "udp": "udp_ok", "dpi": "dpi_none"}
        }
        return scenarios.get(name, scenarios["normal"])