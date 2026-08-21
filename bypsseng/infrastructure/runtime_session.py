


import socket
import logging
from typing import Optional, Dict

logger = logging.getLogger("NetAnalyzer")

class RuntimeSession:
    """
    Section 18: Encapsulates dynamic port allocation and temporary runtime state.
    Replaces global mutable state (LOCAL_HTTP_PORT, LOCAL_SOCKS_PORT).
    Section 15: Supports multi-process strategies via auxiliary ports.
    """
    def __init__(self):
        self._reserved_sockets = []
        self.local_socks_port: Optional[int] = None
        self.local_http_port: Optional[int] = None
        

        self.auxiliary_ports: Dict[str, int] = {}

    def _reserve_port(self) -> int:
        """Reserves a random available port from the OS."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        s.listen(1)
        self._reserved_sockets.append(s)
        return s.getsockname()[1]

    def setup_dynamic_ports(self):
        """Allocates and reserves both SOCKS and HTTP ports."""
        self.release_reserved_ports()
        self.local_socks_port = self._reserve_port()
        self.local_http_port = self._reserve_port()
        logger.info(f"RuntimeSession: Allocated ports -> SOCKS: {self.local_socks_port}, HTTP: {self.local_http_port}")
        return self.local_socks_port, self.local_http_port

    def register_auxiliary_port(self, name: str) -> int:
        """
        Reserves an auxiliary port for multi-process strategies.
        Example: DNSTT needs a local port to establish its internal DNS tunnel.
        """
        port = self._reserve_port()
        self.auxiliary_ports[name] = port
        logger.debug(f"RuntimeSession: Allocated auxiliary port for '{name}': {port}")
        return port

    def release_reserved_ports(self):
        """Releases all reserved ports back to the OS."""
        for s in self._reserved_sockets:
            try: 
                s.close()
            except Exception as e: 
                logger.debug(f"Error closing reserved port socket: {e}")
        
        self._reserved_sockets.clear()
        self.local_socks_port = None
        self.local_http_port = None
        self.auxiliary_ports.clear()