"""Centralized Logging System"""
import logging
import os
from logging.handlers import RotatingFileHandler

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORAMA = True
except:
    COLORAMA = False
    class Fore:
        CYAN = GREEN = YELLOW = RED = ''
    class Style:
        RESET_ALL = BRIGHT = ''

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': Fore.CYAN, 'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW, 'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    } if COLORAMA else {}
    
    def format(self, record):
        if COLORAMA and record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)

class SecurityLogger:
    def __init__(self, name, log_dir="logs", debug_mode=False):
        self.name = name
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if debug_mode else logging.INFO)
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(ColoredFormatter('%(levelname)-8s | %(name)-20s | %(message)s'))
        
        log_file = os.path.join(self.log_dir, f"{self.name}.log")
        file_h = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        file_h.setLevel(logging.DEBUG)
        file_h.setFormatter(logging.Formatter('%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s'))
        
        self.logger.addHandler(console)
        self.logger.addHandler(file_h)
    
    def debug(self, msg, **kw): self.logger.debug(msg, **kw)
    def info(self, msg, **kw): self.logger.info(msg, **kw)
    def warning(self, msg, **kw): self.logger.warning(msg, **kw)
    def error(self, msg, **kw): self.logger.error(msg, **kw)
    def critical(self, msg, **kw): self.logger.critical(msg, **kw)
    def exception(self, msg, **kw): self.logger.exception(msg, **kw)
    
    def log_section(self, title):
        sep = "=" * 60
        self.info(f"\n{sep}\n{title.center(60)}\n{sep}")
    
    def log_subsection(self, title):
        self.info(f"\n{title}\n{'-'*60}")
    
    def log_control_result(self, cid, name, status, details=""):
        sym = {'pass':'✓', 'fail':'✗', 'not_tested':'○'}.get(status.lower(), '?')
        color = {'pass':Fore.GREEN, 'fail':Fore.RED, 'not_tested':Fore.YELLOW}.get(status.lower(), '') if COLORAMA else ''
        msg = f"{sym} [{cid}] {name}: {color}{status.upper()}{Style.RESET_ALL if COLORAMA else ''}"
        if details: msg += f" - {details}"
        self.info(msg)
    
    def log_tool_execution(self, tool, cmd, status="started"):
        if status == "started": self.info(f"🔧 Executing {tool}: {cmd}")
        elif status == "completed": self.info(f"✓ {tool} completed")
        elif status == "failed": self.error(f"✗ {tool} failed")
    
    def log_summary(self, total, passed, failed, not_tested):
        self.log_section("TEST SUMMARY")
        self.info(f"Total: {total} | Passed: {passed} | Failed: {failed} | Not Tested: {not_tested}")
        if total > 0:
            self.info(f"Pass Rate: {(passed/total)*100:.1f}%")

def get_logger(name, debug_mode=False):
    return SecurityLogger(name, debug_mode=debug_mode)
