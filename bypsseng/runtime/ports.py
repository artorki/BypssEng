import socket
from core.logger import log

_port_sockets = []

def setup_dynamic_ports():
    release_reserved_ports()
    def reserve_port():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        s.listen(1)
        _port_sockets.append(s)
        return s.getsockname()[1]
    
    socks = reserve_port()
    http = reserve_port()
    log(f"Allocated and reserved dynamic ports -> SOCKS: {socks}, HTTP: {http}", "INFO")
    return socks, http

def release_reserved_ports():
    for s in _port_sockets:
        try: s.close()
        except Exception: pass
    _port_sockets.clear()
