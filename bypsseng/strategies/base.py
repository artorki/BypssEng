from abc import ABC, abstractmethod

class Strategy(ABC):
    def __init__(self, creds, all_configs=None, dpi_state='none', local_socks_port=None, local_http_port=None, data_dir=None, binary_paths=None):
        self.creds = creds
        self.all_configs = all_configs
        self.dpi_state = dpi_state
        self.local_socks_port = local_socks_port
        self.local_http_port = local_http_port
        self.data_dir = data_dir
        self.binary_paths = binary_paths if binary_paths else {}
        self.binary_name = "unknown"

    @abstractmethod
    async def prepare(self) -> tuple: pass

    @abstractmethod
    async def prepare(self) -> str: pass

    @abstractmethod
    def get_command_args(self, binary_path: str, config_path: str) -> list: pass

    async def start(self): pass
    async def stop(self): pass
    async def health_check(self): pass
    async def get_metrics(self): pass
    
    def get_binary_path(self):
        return self.binary_paths.get(self.binary_name)

    def get_command_args(self, binary_path: str, abs_config_file: str) -> list:
        if self.binary_name == "tor": return [binary_path, '-f', abs_config_file]
        elif self.binary_name == "hysteria": return [binary_path, 'client', '-c', abs_config_file]
        elif self.binary_name == "tuic": return [binary_path, '-c', abs_config_file]
        elif self.binary_name == "naive": return [binary_path, abs_config_file]
        elif self.binary_name == "psiphon": return [binary_path, '-config', abs_config_file]
        else: return [binary_path, 'run', '-c', abs_config_file]