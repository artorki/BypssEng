import asyncio
import platform
import logging
from core.logger import log
from engine.models import DiagnosisResult

logger = logging.getLogger("NetAnalyzer")

async def test_kernel_dpi():
    system = platform.system().lower()
    if system == 'windows':
        try:
            import pydivert
            filter_str = "tcp.RST"
            try:
                w = pydivert.WinDivert(filter_str)
                w.open()
                log("  -> [Kernel DPI] Listening for RST packets via WinDivert...", "INFO")
                
                loop = asyncio.get_running_loop()
                
                def listen():
                    try:
                        packet = w.recv()
                        w.send(packet)
                        return True
                    except Exception:
                        return False
                    finally:
                        w.close()
                
                try:
                    result = await asyncio.wait_for(loop.run_in_executor(None, listen), timeout=2.0)
                    if result:
                        log("  -> [Kernel DPI] RST packet detected! Confirmed DPI attack.", "FAIL")
                        return DiagnosisResult(condition="dpi_aggressive", confidence=1.0, evidence=["kernel_rst_detected"], severity="critical")
                    else:
                        log("  -> [Kernel DPI] No RST packets detected.", "PASS")
                        return DiagnosisResult(condition="dpi_none", confidence=0.95, evidence=[], severity="none")
                except asyncio.TimeoutError:
                    log("  -> [Kernel DPI] Timeout. No RST detected.", "PASS")
                    return DiagnosisResult(condition="dpi_none", confidence=0.9, evidence=[], severity="none")
            except Exception as e:
                log(f"  -> [Kernel DPI] WinDivert driver error: {e}. Falling back.", "WARN")
                return None
        except ImportError:
            log("  -> [Kernel DPI] pydivert not installed. Install it via pip.", "WARN")
            return None
    return None
