from enum import Enum
from typing import Optional, Dict, Any
from strategies.adapters.xray import XrayStrategy
from strategies.adapters.hysteria import HysteriaStrategy
from strategies.adapters.tuic import TuicStrategy
from strategies.adapters.naive import NaiveStrategy
from strategies.adapters.tor import TorStrategy
from strategies.adapters.psiphon import PsiphonStrategy
from strategies.adapters.dnstt import DnsttStrategy
import logging

logger = logging.getLogger("NetAnalyzer")


class StrategyStatus(Enum):
    ACTIVE = 1
    EXPERIMENTAL = 2
    DEPRECATED = 3
    REMOVED = 4


class StrategyRegistry:
    def __init__(self):
        self._registry: Dict[str, Dict[str, Any]] = {}

    def register(self, name: str, strategy_class, status: StrategyStatus):

        if status in [StrategyStatus.ACTIVE, StrategyStatus.EXPERIMENTAL]:
            self._registry[name] = {"class": strategy_class, "status": status}
            logger.debug(f"Strategy '{name}' registered with status: {status.name}")
        else:
            logger.info(
                f"Strategy '{name}' is {status.name} and not available in registry."
            )

    def get_strategy(
        self,
        creds: Dict[str, Any],
        all_configs: list = None,
        dpi_state: str = "none",
        local_socks_port: int = None,
        local_http_port: int = None,
        data_dir: str = None,
        binary_paths: Dict[str, str] = None,
    ) -> Optional[object]:

        proto = creds.get("protocol")
        entry = self._registry.get(proto)

        if not entry:
            logger.error(
                f"Protocol '{proto}' is not registered or is DEPRECATED/REMOVED."
            )
            return None

        strategy_class = entry["class"]
        return strategy_class(
            creds,
            all_configs,
            dpi_state,
            local_socks_port,
            local_http_port,
            data_dir,
            binary_paths,
        )


registry = StrategyRegistry()


registry.register("vless", XrayStrategy, StrategyStatus.ACTIVE)
registry.register("trojan", XrayStrategy, StrategyStatus.ACTIVE)
registry.register("vmess", XrayStrategy, StrategyStatus.ACTIVE)
registry.register("ss", XrayStrategy, StrategyStatus.ACTIVE)
registry.register("shadowtls", XrayStrategy, StrategyStatus.ACTIVE)
registry.register("warp", XrayStrategy, StrategyStatus.ACTIVE)
registry.register("warp_over_reality", XrayStrategy, StrategyStatus.ACTIVE)
registry.register("cloudflare_worker", XrayStrategy, StrategyStatus.ACTIVE)

registry.register("hysteria2", HysteriaStrategy, StrategyStatus.ACTIVE)
registry.register("hy2", HysteriaStrategy, StrategyStatus.ACTIVE)

registry.register("tuic", TuicStrategy, StrategyStatus.ACTIVE)

registry.register("naive", NaiveStrategy, StrategyStatus.ACTIVE)
registry.register("naive+https", NaiveStrategy, StrategyStatus.ACTIVE)

registry.register("tor_proxy", TorStrategy, StrategyStatus.ACTIVE)
registry.register("tor_snowflake", TorStrategy, StrategyStatus.ACTIVE)

registry.register("psiphon", PsiphonStrategy, StrategyStatus.ACTIVE)

registry.register("dnstt", DnsttStrategy, StrategyStatus.ACTIVE)


def get_strategy(
    creds: Dict[str, Any],
    all_configs: list = None,
    dpi_state: str = "none",
    local_socks_port: int = None,
    local_http_port: int = None,
    data_dir: str = None,
    binary_paths: Dict[str, str] = None,
) -> Optional[object]:
    return registry.get_strategy(
        creds,
        all_configs,
        dpi_state,
        local_socks_port,
        local_http_port,
        data_dir,
        binary_paths,
    )
