


import asyncio
import platform
import logging
from core.logger import log
from bypsseng.domain.models import DiagnosisResult
from bypsseng.domain.conditions import NetworkCondition

logger = logging.getLogger("NetAnalyzer")

async def test_kernel_dpi():
    """
    Section 1: Kernel-level DPI Detection (WinDivert).
    Listens for injected RST packets and analyzes TTL anomalies.
    Falls back to behavioral test (returns None) if driver is missing.
    """
    system = platform.system().lower()
    if system == 'windows':
        try:
            import pydivert

            filter_str = "inbound and tcp.Rst"
            try:
                w = pydivert.WinDivert(filter_str)
                w.open()
                log("  -> [Kernel DPI] Listening for RST packets via WinDivert...", "INFO")
                
                loop = asyncio.get_running_loop()
                
                def listen():
                    try:
                        packet = w.recv()



                        if packet.tcp.rst:
                            ttl = packet.ip.ttl
                            seq = packet.tcp.seq_num
                            logger.debug(f"[Kernel DPI] RST captured. TTL: {ttl}, Seq: {seq}")
                            


                            if ttl < 100:
                                w.send(packet) # Pass it through after analysis
                                return True, ttl, seq
                            w.send(packet)
                    except Exception:
                        return False, None, None
                    finally:
                        w.close()
                

                try:
                    result = await asyncio.wait_for(loop.run_in_executor(None, listen), timeout=2.0)
                    if result and result[0]:
                        ttl_val = result[1]
                        seq_val = result[2]
                        log("  -> [Kernel DPI] Injected RST with abnormal TTL detected! Confirmed DPI attack.", "FAIL")

                        return DiagnosisResult(
                            condition=NetworkCondition.DPI_AGGRESSIVE.value, 
                            confidence=1.0, 
                            evidence=["kernel_rst_abnormal_ttl", f"ttl={ttl_val}", f"seq={seq_val}"], 
                            severity="critical"
                        )
                    else:
                        log("  -> [Kernel DPI] No abnormal RST packets detected.", "PASS")
                        return DiagnosisResult(
                            condition=NetworkCondition.DPI_NONE.value, 
                            confidence=0.95, 
                            evidence=[], 
                            severity="none"
                        )
                except asyncio.TimeoutError:
                    log("  -> [Kernel DPI] Timeout. No RST detected.", "PASS")
                    return DiagnosisResult(
                        condition=NetworkCondition.DPI_NONE.value, 
                        confidence=0.9, 
                        evidence=[], 
                        severity="none"
                    )
                    
            except Exception as e:
                log(f"  -> [Kernel DPI] WinDivert driver error: {e}. Falling back.", "WARN")

                return None
        except ImportError:
            log("  -> [Kernel DPI] pydivert not installed. Install it via pip.", "WARN")
            return None
    else:

        logger.debug("Kernel DPI not implemented for this OS. Falling back.")
        return None