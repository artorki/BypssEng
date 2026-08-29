import time
import logging
import logging.handlers
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
    _LEVEL_MAP = {
        logging.DEBUG: "TRACE", logging.INFO: "INFO",
        logging.WARNING: "WARN", logging.ERROR: "FAIL",
        logging.CRITICAL: "FAIL", TRACE_LEVEL_NUM: "TRACE",
    }
    def __init__(self, sink):
        super().__init__()
        self.sink = sink
    def emit(self, record):
        try:
            self.sink(record.getMessage(), self._LEVEL_MAP.get(record.levelno, "INFO"))
        except Exception:
            pass

def setup_file_logging(log_file="netanalyzer.log", level=logging.DEBUG,
                       maxBytes=5 * 1024 * 1024, backupCount=3):
    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_file,
        maxBytes=maxBytes,
        backupCount=backupCount,
        encoding="utf-8"
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    )
    logger.addHandler(file_handler)

    if logger.level == logging.NOTSET or logger.level > level:
        logger.setLevel(level)

    return file_handler