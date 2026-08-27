import asyncio
import logging
import os

from strategies.base import Strategy

logger = logging.getLogger("NetAnalyzer")

_bootstrap_logger = logging.getLogger("BootstrapTor")

_SNOWFLAKE_BRIDGE_LINES = (
    "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.org,ajax.aspnetcdn.com ice=stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn\n"
    "Bridge snowflake 192.0.2.4:80 8838024498816A039B6BFE708B038F529C86E3B9 fingerprint=8838024498816A039B6BFE708B038F529C86E3B9 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.org,ajax.aspnetcdn.com ice=stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn\n"
)


async def start_bootstrap_tor(socks_port, tor_binary, snowflake_binary=None, data_dir=None, bootstrap_timeout=90.0):

    if not tor_binary or not os.path.isfile(tor_binary):
        _bootstrap_logger.warning("Bootstrap Tor: tor binary not found.")
        return None, None

    data_dir = data_dir or os.path.join(os.getcwd(), "bootstrap_tor")
    os.makedirs(data_dir, exist_ok=True)
    torrc_path = os.path.join(data_dir, "bootstrap_torrc")

    def _tor_path(p): return p.replace("\\", "/")

    torrc_lines = [
        f"SocksPort 127.0.0.1:{socks_port}",
        f'DataDirectory "{_tor_path(data_dir)}"',
        "AvoidDiskWrites 1",
        "Log notice stdout",
    ]
    if snowflake_binary and os.path.isfile(snowflake_binary):
        torrc_lines.append("UseBridges 1")
        torrc_lines.append(f'ClientTransportPlugin snowflake exec "{_tor_path(snowflake_binary)}"')
        torrc_lines.extend(_SNOWFLAKE_BRIDGE_LINES.splitlines())

    proc = None
    try:
        with open(torrc_path, "w", encoding="utf-8") as f:
            f.write("\n".join(torrc_lines) + "\n")

        proc = await asyncio.create_subprocess_exec(
            tor_binary, "-f", torrc_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=data_dir,
        )

        async def _drain(stream, label):
            try:
                while True:
                    raw = await stream.readline()
                    if not raw:
                        break
                    text = raw.decode(errors="ignore").strip()
                    if any(k in text.lower() for k in ("error", "warn", "failed")):
                        _bootstrap_logger.info(f"[bootstrap-tor:{label}] {text}")
            except Exception:
                pass

        asyncio.create_task(_drain(proc.stderr, "STDERR"))

        loop = asyncio.get_running_loop()
        deadline = loop.time() + bootstrap_timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError(f"Tor did not bootstrap within {bootstrap_timeout}s")
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
            if not line:
                raise RuntimeError("Tor exited before a circuit was established")
            if b"Bootstrapped 100%" in line:
                break

        asyncio.create_task(_drain(proc.stdout, "STDOUT"))

        socks_url = f"socks5://127.0.0.1:{socks_port}"
        _bootstrap_logger.info(f"Bootstrap Tor is up at {socks_url}")
        return proc, socks_url
    except Exception as e:
        _bootstrap_logger.warning(f"Bootstrap Tor could not be started: {e}")
        await _terminate_bootstrap_proc(proc)
        return None, None


async def _terminate_bootstrap_proc(proc, timeout=10):

    if proc is None or proc.returncode is not None:
        return
    try:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
    except Exception as e:
        _bootstrap_logger.debug(f"Bootstrap Tor termination error: {e}")


class TorStrategy(Strategy):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.binary_name = "tor"

    async def prepare(self) -> tuple:

        creds = self.creds
        tor_data_dir = os.path.join(self.data_dir, "tor_data").replace("\\", "/")

        if creds["protocol"] == "tor_snowflake":
            snowflake_path = self.binary_paths.get("snowflake")
            lyrebird_path = self.binary_paths.get("lyrebird")

            if snowflake_path and os.path.isfile(snowflake_path):

                torrc_content = (
                    f"DataDirectory {tor_data_dir}\n"
                    f"SocksPort 127.0.0.1:{self.local_socks_port}\n"
                    f"HTTPTunnelPort 127.0.0.1:{self.local_http_port}\n"
                    f"UseBridges 1\n"
                    f"ClientTransportPlugin snowflake exec {snowflake_path}\n"
                    f"Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.org,ajax.aspnetcdn.com ice=stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn\n"
                    f"Bridge snowflake 192.0.2.4:80 8838024498816A039B6BFE708B038F529C86E3B9 fingerprint=8838024498816A039B6BFE708B038F529C86E3B9 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.org,ajax.aspnetcdn.com ice=stun:stun.l.google.com:19302 utls-imitate=hellorandomizedalpn\n"
                )
                config_name = "torrc_snowflake"
            elif lyrebird_path and os.path.isfile(lyrebird_path):

                torrc_content = (
                    f"DataDirectory {tor_data_dir}\n"
                    f"SocksPort 127.0.0.1:{self.local_socks_port}\n"
                    f"HTTPTunnelPort 127.0.0.1:{self.local_http_port}\n"
                    f"UseBridges 1\n"
                    f"ClientTransportPlugin obfs4 exec {lyrebird_path}\n"
                    f"Bridge obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1\n"
                    f"Bridge obfs4 38.229.1.78:80 C8CBDB2464FC9804A69531437BCF2BE31FDD2EE4 cert=AA1+Qiae9pr5f17V01d3XvqP5yzP3Y5Dqdpf17TrHpWhVZ0ggpfpXQAU5ADQ iat-mode=1\n"
                )
                config_name = "torrc_obfs4"
            else:
                logger.error("Tor: Missing snowflake and lyrebird binaries.")
                return None, None
        else:

            torrc_content = (
                f"DataDirectory {tor_data_dir}\n"
                f"SocksPort 127.0.0.1:{self.local_socks_port}\n"
                f"HTTPTunnelPort 127.0.0.1:{self.local_http_port}\n"
            )
            config_name = "torrc_proxy"

        config_file = f"{config_name}"
        with open(os.path.join(self.data_dir, config_file), "w") as f:
            f.write(torrc_content)

        self._config_file = config_file

        return config_file, "tor"