


import time
import logging
import os
import platform
import json


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




class StructuredJsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage()
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)

def setup_file_logging(log_file_path):
    """Configures structured JSON logging to a file with rotation."""
    log_dir = os.path.dirname(log_file_path)
    os.makedirs(log_dir, exist_ok=True)
    
    handler = logging.handlers.RotatingFileHandler(
        filename=log_file_path, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
    )
    handler.setFormatter(StructuredJsonFormatter())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.DEBUG) # Capture everything for support logs


logger = logging.getLogger("NetAnalyzer")

def log(msg, type="INFO", color_override=None):
    """
    Human-readable colored console output.
    Also forwards to structured file logger.
    """
    color = color_override if color_override else Colors.ENDC
    if type == "HEADER": color = Colors.HEADER
    elif type == "PASS": color = Colors.OKGREEN
    elif type == "WARN": color = Colors.WARNING
    elif type in ("FAIL", "ERROR"): color = Colors.FAIL
    elif type == "SOL": color = Colors.OKCYAN
    

    print(f"{color}[{time.strftime('%H:%M:%S')}] [{type}] {msg}{Colors.ENDC}")
    


    log_type_map = {
        "HEADER": logging.INFO,
        "PASS": logging.INFO,
        "WARN": logging.WARNING,
        "FAIL": logging.ERROR,
        "ERROR": logging.ERROR,
        "SOL": logging.INFO,
        "INFO": logging.INFO,
        "TRACE": TRACE_LEVEL_NUM,
        "DEBUG": logging.DEBUG
    }
    log_level = log_type_map.get(type, logging.INFO)
    logger.log(log_level, msg)