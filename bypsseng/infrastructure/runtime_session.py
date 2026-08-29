import socket
import logging
from typing import Optional, Dict

logger = logging.getLogger("NetAnalyzer")

class RuntimeSession:

    def __init__(self):
        self._reserved_sockets = []
        self.local_socks_port: Optional[int] = None
        self.local_http_port: Optional[int] = None

        self.auxiliary_ports: Dict[str, int] = {}

    def _reserve_port(self) -> int:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        self._reserved_sockets.append(s)
        return s.getsockname()[1]

    def setup_dynamic_ports(self):

        self.release_reserved_ports()
        self.local_socks_port = self._reserve_port()
        self.local_http_port = self._reserve_port()
        logger.info(
            f"RuntimeSession: Allocated ports -> SOCKS: {self.local_socks_port}, HTTP: {self.local_http_port}"
        )
        return self.local_socks_port, self.local_http_port

    def register_auxiliary_port(self, name: str) -> int:

        port = self._reserve_port()
        self.auxiliary_ports[name] = port
        logger.debug(f"RuntimeSession: Allocated auxiliary port for '{name}': {port}")
        return port

    def release_reserved_ports(self):

        for s in self._reserved_sockets:
            try:
                s.close()
            except Exception as e:
                logger.debug(f"Error closing reserved port socket: {e}")

        self._reserved_sockets.clear()
        self.local_socks_port = None
        self.local_http_port = None
        self.auxiliary_ports.clear()

    def release_binding_sockets(self):
        for s in self._reserved_sockets:
            try:
                s.close()
            except Exception as e:
                logger.debug(f"Error closing reserved port socket: {e}")
        self._reserved_sockets.clear()