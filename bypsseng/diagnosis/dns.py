import asyncio
import socket
import random
import string
import ipaddress
import re
import time
import logging
from core.logger import log
from config.models import CONFIG
from bypsseng.domain.models import DiagnosisResult
from bypsseng.domain.conditions import NetworkCondition

logger = logging.getLogger("NetAnalyzer")


def extract_dns_ips(text):
    ips = []
    for line in text.splitlines():
        if (
            "DNS Servers" in line
            or "Statically Configured DNS" in line
            or "Dynamically Configured DNS" in line
        ):
            for token in re.findall(r"[^\s,;]+", line):
                try:
                    ipaddress.ip_address(token)
                    ips.append(token)
                except ValueError:
                    pass
    if not ips:
        for token in re.findall(r"[^\s,;]+", text):
            try:
                ipaddress.ip_address(token)
                ips.append(token)
            except ValueError:
                pass
    return ips


async def send_dns_query(ip, domain):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    txid = random.randint(0, 65535)
    packet = (
        txid.to_bytes(2, "big")
        + (0x0100).to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + (0).to_bytes(6, "big")
    )
    qname = (
        b"".join(
            [len(part).to_bytes(1, "big") + part.encode() for part in domain.split(".")]
        )
        + b"\x00"
    )
    packet += qname + (1).to_bytes(2, "big") + (1).to_bytes(2, "big")

    start_time = time.time()
    try:
        await loop.sock_sendto(sock, packet, (ip, 53))
        data, _ = await asyncio.wait_for(
            loop.sock_recvfrom(sock, 1024), timeout=CONFIG.intervals.dns_timeout
        )
        latency = round((time.time() - start_time) * 1000, 2)
        if len(data) < 12:
            return None
        flags = int.from_bytes(data[2:4], "big")
        if not (flags & 0x8000):
            return None
        rcode = flags & 0xF
        ancount = int.from_bytes(data[6:8], "big")
        resp_txid = int.from_bytes(data[:2], "big")
        return {
            "rcode": rcode,
            "ancount": ancount,
            "txid": resp_txid,
            "expected_txid": txid,
            "latency": latency,
        }
    except asyncio.TimeoutError:
        return None
    except Exception as e:
        logger.debug(f"DNS query error: {e}")
        return None
    finally:
        sock.close()


async def scan_fastest_dns():
    log("Scanning for fastest and cleanest DNS servers...", "SOL")
    candidates = CONFIG.targets.dns_candidates

    async def test_dns(ip):
        start = time.time()
        res = await send_dns_query(ip, "example.com")
        if res is None or res.get("rcode", 1) != 0 or res.get("ancount", 0) == 0:
            return None

        rand_res = await send_dns_query(
            ip, "".join(random.choices(string.ascii_lowercase, k=10)) + ".com"
        )
        if rand_res is not None and rand_res.get("ancount", 0) > 0:
            return None
        latency = round((time.time() - start) * 1000, 2)
        return (ip, latency)

    results = await asyncio.gather(
        *[test_dns(ip) for ip in candidates], return_exceptions=True
    )
    valid = [r for r in results if r and not isinstance(r, Exception)]
    valid.sort(key=lambda x: x[1])

    if valid:
        top_ips = [ip for ip, lat in valid[:3]]
        log(f"  -> Fastest DNS: {', '.join(top_ips)}", "PASS")
        return top_ips
    return ["1.1.1.1", "8.8.8.8"]


async def test_doh_resolution():
    import aiohttp

    log("  -> Testing DoH (DNS over HTTPS)...", "INFO")
    results = []
    for doh_url in CONFIG.targets.doh_endpoints:
        try:
            txid = random.randint(0, 65535)
            qname = (
                b"".join(
                    [
                        len(part).to_bytes(1, "big") + part.encode()
                        for part in "example.com".split(".")
                    ]
                )
                + b"\x00"
            )
            packet = (
                txid.to_bytes(2, "big")
                + (0x0100).to_bytes(2, "big")
                + (1).to_bytes(2, "big")
                + (0).to_bytes(6, "big")
            )
            packet += qname + (1).to_bytes(2, "big") + (1).to_bytes(2, "big")
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5)
            ) as session:
                async with session.post(
                    doh_url,
                    data=packet,
                    headers={"Content-Type": "application/dns-message"},
                ) as resp:
                    if resp.status == 200:
                        data = await resp.read()
                        if len(data) >= 12:
                            flags = int.from_bytes(data[2:4], "big")
                            if not (flags & 0x8000):
                                results.append("unknown")
                                continue
                            resp_txid = int.from_bytes(data[:2], "big")
                            rcode = flags & 0xF
                            ancount = int.from_bytes(data[6:8], "big")
                            if resp_txid == txid and rcode == 0 and ancount > 0:
                                results.append("ok")
                            else:
                                results.append("unknown")
                        else:
                            results.append("unknown")
                    else:
                        results.append("dropped")
        except asyncio.TimeoutError:
            results.append("dropped")
        except Exception as e:
            logger.debug(f"DoH error: {e}")
            results.append("unknown")

    if not results:
        return "unknown"
    if "ok" in results:
        return "ok"
    if all(r == "dropped" for r in results):
        return "dropped"
    return "unknown"


async def resolve_via_doh(domain):
    import aiohttp

    doh_servers = [
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/dns-query",
        "https://9.9.9.9/dns-query",
    ]
    for doh in doh_servers:
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5)
            ) as session:
                async with session.get(
                    f"{doh}?name={domain}&type=A",
                    headers={"accept": "application/dns-json"},
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for answer in data.get("Answer", []):
                            if answer.get("type") == 1:
                                return answer["data"]
        except Exception as e:
            logger.debug(f"DoH resolve error on {doh} for {domain}: {e}")
    return None


async def test_dns_layer():

    log("Phase 2: Checking DNS Layer (Hijack Detection via Local vs DoH)...", "HEADER")

    loop = asyncio.get_running_loop()
    system_dns_ok = False
    try:
        await loop.getaddrinfo("www.google.com", 443)
        system_dns_ok = True
    except Exception:
        system_dns_ok = False

    if not system_dns_ok:
        log("  -> System DNS cannot resolve www.google.com!", "WARN")

    dns_ip = random.choice(CONFIG.targets.external_ips)

    res = await send_dns_query(dns_ip, "example.com")
    udp_latency = res.get("latency") if res else None

    if res is None:
        udp_status = "dropped"
    elif res.get("txid") != res.get("expected_txid"):
        udp_status = "unknown"
    elif res["rcode"] != 0 and res["ancount"] == 0:
        udp_status = "unknown"
    else:
        udp_status = "ok"

    doh_res = await test_doh_resolution()
    local_res_ips = None

    rand_domain = "".join(random.choices(string.ascii_lowercase, k=10)) + ".com"
    try:
        local_res_ips = await loop.getaddrinfo(rand_domain, None)
    except socket.gaierror:
        pass
    except Exception as e:
        logger.error(f"Unexpected DNS resolution error: {e}")

    evidence = [
        f"udp_latency={udp_latency}ms" if udp_latency else "udp_latency=timeout",
        f"doh_res={doh_res}",
    ]

    if local_res_ips:
        public_found = False
        for fam, _, _, _, sockaddr in local_res_ips:
            ip = sockaddr[0]
            if (
                ip.startswith("10.")
                or ip.startswith("172.")
                or ip.startswith("192.168.")
                or ip == "127.0.0.1"
            ):
                continue
            public_found = True
        if public_found:
            return DiagnosisResult(
                condition=NetworkCondition.DNS_HIJACKED.value,
                confidence=0.95,
                evidence=evidence + ["public_ip_returned_for_random_domain"],
                severity="high",
            )

    if not system_dns_ok:
        if udp_status == "ok" or doh_res == "ok":
            log("  -> System DNS broken but direct DNS works. Needs fix.", "WARN")
            return DiagnosisResult(
                condition=NetworkCondition.DNS_SYSTEM_BROKEN.value,
                confidence=0.80,
                evidence=evidence + ["system_dns_failed", "alternate_dns_ok"],
                severity="medium",
            )

    if udp_status == "dropped" and doh_res == "ok":
        return DiagnosisResult(
            condition=NetworkCondition.UDP_DNS_BLOCKED.value,
            confidence=0.85,
            evidence=evidence + ["udp_dns_dropped", "doh_reachable"],
            severity="medium",
        )
    if udp_status == "dropped" and doh_res == "dropped":
        return DiagnosisResult(
            condition=NetworkCondition.DNS_DROPPED.value,
            confidence=0.90,
            evidence=evidence + ["udp_dropped", "doh_dropped"],
            severity="high",
        )

    if udp_status == "unknown" or doh_res == "unknown":
        return DiagnosisResult(
            condition=NetworkCondition.DNS_UNKNOWN.value,
            confidence=0.5,
            evidence=evidence + ["conflicting_observations"],
            severity="low",
        )

    return DiagnosisResult(
        condition=NetworkCondition.DNS_OK.value,
        confidence=1.0,
        evidence=evidence,
        severity="none",
    )
