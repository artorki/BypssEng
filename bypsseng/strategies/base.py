


import os
from abc import ABC, abstractmethod
from typing import List, Dict, Any
import logging

logger = logging.getLogger("NetAnalyzer")

class Strategy(ABC):
    """
    Strategy Definition Interface (HANDOFF Sec 15, 16, 58)
    
    Ownership Lifecycle:
    - RuntimeManager owns OS process
    - Strategy owns strategy definition (config, dependencies, commands)
    - Orchestrator owns state
    
    Supports multi-process strategies (e.g., DNSTT).
    """
    def __init__(self, creds: Dict[str, Any], all_configs: List[Dict[str, Any]] = None, dpi_state: str = 'none', 
                 local_socks_port: int = None, local_http_port: int = None, data_dir: str = None, binary_paths: Dict[str, str] = None):
        self.creds = creds
        self.all_configs = all_configs
        self.dpi_state = dpi_state
        self.local_socks_port = local_socks_port
        self.local_http_port = local_http_port
        self.data_dir = data_dir
        self.binary_paths = binary_paths if binary_paths else {}
        self.binary_name = "unknown"
        

        self._config_file = None

    @abstractmethod
    async def prepare(self) -> tuple:
        """
        Prepares configuration files for the strategy.
        Must return a tuple of (config_filename, binary_name).
        """
        pass
    
    def dependencies(self) -> List[str]:
        """
        Returns a list of required binaries or auxiliary files for this strategy.
        (HANDOFF Sec 15: Allows strategies like DNSTT to declare multi-file dependencies)
        """
        return [self.binary_name]

    def processes(self) -> List[List[str]]:
        """
        Returns a list of command arguments arrays to start processes.
        Supports multi-process strategies (e.g., Xray + DNSTT-client).
        (HANDOFF Sec 15)
        """
        binary_path = self.get_binary_path()
        if not binary_path or not self._config_file:
            return []
            
        abs_config_file = os.path.join(self.data_dir, self._config_file)
        return [self.get_command_args(binary_path, abs_config_file)]

    def get_binary_path(self) -> str:
        return self.binary_paths.get(self.binary_name)

    def get_command_args(self, binary_path: str, abs_config_file: str) -> List[str]:
        if self.binary_name == "tor": return [binary_path, '-f', abs_config_file]
        elif self.binary_name == "hysteria": return [binary_path, 'client', '-c', abs_config_file]
        elif self.binary_name == "tuic": return [binary_path, '-c', abs_config_file]
        elif self.binary_name == "naive": return [binary_path, abs_config_file]
        elif self.binary_name == "psiphon": return [binary_path, '-config', abs_config_file]
        else: return [binary_path, 'run', '-c', abs_config_file]

    async def start(self):
        """
        Lifecycle hook called before process execution.
        Can be overridden for specific pre-start logic.
        (HANDOFF Sec 16)
        """
        pass

    async def stop(self):
        """
        Lifecycle hook called after process termination.
        Can be overridden for specific post-stop logic.
        """
        pass
        
    async def health_check(self):
        """
        Delegates to RuntimeManager or implements strategy-specific health check.
        """
        pass

    async def get_metrics(self):
        """
        Returns strategy-specific metrics (e.g., active connections, latency).
        """
        pass

    async def cleanup(self):
        """
        Cleanup auxiliary files, temporary data, or graceful shutdown logic.
        (HANDOFF Sec 15: Ensures no orphan files/processes are left behind)
        """
        pass