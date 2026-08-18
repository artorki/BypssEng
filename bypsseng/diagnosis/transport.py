import asyncio
import socket
from core.logger import log
from config.models import CONFIG
from engine.models import DiagnosisResult

async def test_vpn_ports():
    log("Phase 3: Checking VPN Ports...", "HEADER")
    cf_ip = CONFIG.targets.cf_ip
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(cf_ip, 443), timeout=5)
        writer.close(); await writer.wait_closed()
    except Exception:
        log("  -> Cloudflare IP is unreachable. Port test skipped.", "WARN")
        return DiagnosisResult(condition="vpn_unknown", confidence=0.5, evidence=[], severity="low")

    async def check_port(port):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(cf_ip, port), timeout=5)
            writer.close(); await writer.wait_closed(); return port, True
        except asyncio.TimeoutError: return port, 'timeout'
        except ConnectionRefusedError: return port, False
        except Exception as e:
            import logging
            logging.getLogger("NetAnalyzer").debug(f"Port check error: {e}")
            return port, False
            
    results = await asyncio.gather(*[check_port(p) for p in [1194, 1701, 1723, 443, 80]])
    blocked = [p for p, res in results if res is False]
    timed_out = [p for p, res in results if res == 'timeout']
    if len(blocked) + len(timed_out) == 5: 
        return DiagnosisResult(condition="vpn_blocked", confidence=0.9, evidence=["all_test_ports_blocked"], severity="medium")
    elif blocked: 
        return DiagnosisResult(condition="vpn_partial", confidence=0.75, evidence=["some_ports_blocked"], severity="low")
    
    return DiagnosisResult(condition="vpn_ok", confidence=1.0, evidence=[], severity="none")

async def test_udp_status():
    from diagnosis.dns import send_dns_query
    results = []
    for ip in CONFIG.targets.external_ips:
        res = await send_dns_query(ip, 'example.com')
        if res is not None and res.get('ancount', 0) > 0 and res.get('txid') == res.get('expected_txid'):
            results.append('ok')
        elif res is None:
            results.append('dropped')
        else:
            results.append('unknown')

    if 'ok' in results:
        return DiagnosisResult(condition="udp_ok", confidence=1.0, evidence=[], severity="none")
    if all(r == 'dropped' for r in results):
        return DiagnosisResult(condition="udp_dropped", confidence=0.9, evidence=["dns_udp_queries_failed"], severity="high")
    return DiagnosisResult(condition="udp_unknown", confidence=0.5, evidence=[], severity="low")

def _sync_test_warp_udp(test_endpoints):
    reachable = 0
    wg_packet = b'\x01\x00\x00\x00'
    for ip, port in test_endpoints:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(wg_packet, (ip, port))
            try:
                data, _ = sock.recvfrom(1024)
                if len(data) > 0:
                    reachable += 1
            except socket.timeout:
                pass
            except ConnectionRefusedError:
                pass
            sock.close()
        except Exception:
            pass
    if reachable >= 2: return 'ok'
    elif reachable >= 1: return 'partial'
    return 'dropped'

async def test_warp_udp_reachability():
    test_endpoints = [
        ("162.159.192.1", 2408), ("162.159.193.1", 2408), ("188.114.96.1", 2408),
        ("162.159.192.1", 4500), ("162.159.193.1", 500)
    ]
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, _sync_test_warp_udp, test_endpoints)
    
    if res == 'ok': return DiagnosisResult(condition="warp_ok", confidence=1.0, evidence=[], severity="none")
    if res == 'partial': return DiagnosisResult(condition="warp_partial", confidence=0.75, evidence=[], severity="low")
    return DiagnosisResult(condition="warp_dropped", confidence=0.9, evidence=[], severity="medium")

def _sync_test_udp_443_probe(target_ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        packet = b'\xc0\x00\x00\x00\x01\x08' + b'\x12\x34\x56\x78\x9a\xbc\xde\xf0' + b'\x00\x00\x00\x29\x00\x00\x00\x01\x06\x00\x05\x00\x00\x00\x00\x00'
        sock.sendto(packet, (target_ip, 443))
        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            return 'reachable' if len(data) > 0 else 'unknown'
        except socket.timeout:
            sock.close()
            return 'unknown'
        except ConnectionRefusedError:
            sock.close()
            return 'dropped'
    except Exception:
        return 'unknown'

async def test_udp_443_probe():
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, _sync_test_udp_443_probe, CONFIG.targets.google_ip)
    
    if res == 'reachable': return DiagnosisResult(condition="quic_reachable", confidence=1.0, evidence=[], severity="none")
    if res == 'dropped': return DiagnosisResult(condition="quic_dropped", confidence=0.9, evidence=[], severity="medium")
    return DiagnosisResult(condition="quic_unknown", confidence=0.5, evidence=[], severity="low")
