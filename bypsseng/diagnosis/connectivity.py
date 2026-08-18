import asyncio
import re
import platform
from core.logger import log
from config.models import CONFIG

async def test_icmp(ip):
    system = platform.system().lower()
    cmd = ['ping', '-n', '1', '-w', '2000', ip] if system == 'windows' else ['ping', '-c', '1', '-W', '2', ip]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await asyncio.wait_for(proc.communicate(), timeout=3)
        return proc.returncode == 0
    except Exception as e:
        import logging
        logging.getLogger("NetAnalyzer").debug(f"ICMP error: {e}")
        return False

async def get_icmp_latency(ip):
    import time
    system = platform.system().lower()
    cmd = ['ping', '-n', '1', '-w', '2000', ip] if system == 'windows' else ['ping', '-c', '1', '-W', '2', ip]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
        if proc.returncode == 0:
            output = stdout.decode(errors='ignore')
            match = re.search(r'(?:time|زمان)\s*[=<]\s*(\d+\.?\d*)\s*ms', output)
            if match:
                return float(match.group(1))
        return None
    except Exception as e:
        import logging
        logging.getLogger("NetAnalyzer").debug(f"ICMP latency error: {e}")
        return None

async def test_tcp_ping(ip, port=443):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=CONFIG.intervals.tcp_timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception as e:
        import logging
        logging.getLogger("NetAnalyzer").debug(f"TCP ping error to {ip}:{port}: {e}")
        return False

async def test_ip_layer():
    log("Phase 1: Checking Network & Routing Layer...", "HEADER")
    state = {'internal': False, 'external': False, 'icmp': False, 'tcp_ping': False, 'ipv6': 'unknown'}
    
    async def check_tcp(ip, port):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=CONFIG.intervals.tcp_timeout)
            writer.close(); await writer.wait_closed(); return True
        except Exception: return False

    tcp_ext_tasks_443 = [test_tcp_ping(ip, 443) for ip in CONFIG.targets.external_ips]
    tcp_ext_tasks_80 = [test_tcp_ping(ip, 80) for ip in CONFIG.targets.external_ips]
    tcp_ext_results = await asyncio.gather(*(tcp_ext_tasks_443 + tcp_ext_tasks_80))
    state['tcp_ping'] = any(tcp_ext_results)

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(CONFIG.targets.ipv6_target, 443), timeout=2)
        writer.close(); await writer.wait_closed()
        state['ipv6'] = 'ok'
    except Exception as e:
        import logging
        logging.getLogger("NetAnalyzer").debug(f"IPv6 error: {e}")
        state['ipv6'] = 'dropped'

    icmp_ext_tasks = [test_icmp(ip) for ip in CONFIG.targets.external_ips]
    icmp_int_tasks = [test_icmp(ip) for ip in CONFIG.targets.internal_ips]
    icmp_ext, icmp_int = await asyncio.gather(asyncio.gather(*icmp_ext_tasks), asyncio.gather(*icmp_int_tasks))
    
    has_icmp_ext = any(icmp_ext)
    has_icmp_int = any(icmp_int)
    state['icmp'] = has_icmp_ext or has_icmp_int

    ext_tcp_tasks = [check_tcp(ip, 443) for ip in CONFIG.targets.external_ips]
    ext_tcp_results = await asyncio.gather(*ext_tcp_tasks)
    
    state['external'] = state['tcp_ping'] or has_icmp_ext or any(ext_tcp_results)
    
    internal_tasks = [check_tcp(ip, 53) for ip in CONFIG.targets.internal_ips]
    int_tcp_results = await asyncio.gather(*internal_tasks)
    state['internal'] = has_icmp_int or any(int_tcp_results)
    
    return state
