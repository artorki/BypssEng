import time
import logging
import os
import platform

if platform.system().lower() == 'windows':
    os.system('color')

class Colors:
    HEADER = '\033[95m'; OKBLUE = '\033[94m'; OKCYAN = '\033[96m'; OKGREEN = '\033[92m'
    WARNING = '\033[93m'; FAIL = '\033[91m'; ENDC = '\033[0m'; BOLD = '\033[1m'

TRACE_LEVEL_NUM = 15 
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")
def trace(self, message, *args, **kwargs):
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kwargs)
logging.Logger.trace = trace

logger = logging.getLogger("NetAnalyzer")

def log(msg, type="INFO", color_override=None):

    color = color_override if color_override else Colors.ENDC
    if type == "HEADER": color = Colors.HEADER
    elif type == "PASS": color = Colors.OKGREEN
    elif type == "WARN": color = Colors.WARNING
    elif type in ("FAIL", "ERROR"): color = Colors.FAIL
    elif type == "SOL": color = Colors.OKCYAN
    
    print(f"{color}[{time.strftime('%H:%M:%S')}] [{type}] {msg}{Colors.ENDC}")
    
    log_type_map = {
        "HEADER": logging.INFO, "PASS": logging.INFO, "WARN": logging.WARNING,
        "FAIL": logging.ERROR, "ERROR": logging.ERROR, "SOL": logging.INFO,
        "INFO": logging.INFO, "TRACE": TRACE_LEVEL_NUM, "DEBUG": logging.DEBUG
    }
    logger.log(log_type_map.get(type, logging.INFO), msg)

class BroadcastLogHandler(logging.Handler):

    def __init__(self, hooked_log_func):
        super().__init__()
        self.hooked_log_func = hooked_log_func

    def emit(self, record):
        try:
            type_map = {
                logging.INFO: "INFO", logging.WARNING: "WARN",
                logging.ERROR: "FAIL", logging.DEBUG: "TRACE",
                TRACE_LEVEL_NUM: "TRACE"
            }
            self.hooked_log_func(record.getMessage(), type_map.get(record.levelno, "INFO"))
        except Exception:
            pass
