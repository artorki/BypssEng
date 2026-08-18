import time
import logging
import os
import platform

if platform.system().lower() == 'windows':
    os.system('color')

class Colors:
    HEADER = '\033[95m'; OKBLUE = '\033[94m'; OKCYAN = '\033[96m'; OKGREEN = '\033[92m'; WARNING = '\033[93m'; FAIL = '\033[91m'; ENDC = '\033[0m'; BOLD = '\033[1m'

def log(msg, type="INFO", color_override=None):
    color = color_override if color_override else Colors.ENDC
    if type == "HEADER": color = Colors.HEADER
    elif type == "PASS": color = Colors.OKGREEN
    elif type == "WARN": color = Colors.WARNING
    elif type in ("FAIL", "ERROR"): color = Colors.FAIL
    elif type == "SOL": color = Colors.OKCYAN
    print(f"{color}[{time.strftime('%H:%M:%S')}] [{type}] {msg}{Colors.ENDC}")
    logging.getLogger("NetAnalyzer").info(f"[{type}] {msg}")
