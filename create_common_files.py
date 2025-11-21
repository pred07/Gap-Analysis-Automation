#!/usr/bin/env python3
"""
Installer script - Creates all common utility files
Run: python3 create_common_files.py
"""

import os

print("Creating common utility files...")

# File 1: common/__init__.py
with open('common/__init__.py', 'w') as f:
    f.write('''"""Common utilities package"""
__version__ = "1.0.0"

from .logger import SecurityLogger, get_logger
from .json_writer import JSONWriter, write_module_output, merge_outputs

__all__ = ['SecurityLogger', 'get_logger', 'JSONWriter', 'write_module_output', 'merge_outputs']
''')
print("✓ Created common/__init__.py")

# File 2: common/logger.py
with open('common/logger.py', 'w') as f:
    f.write('''"""Centralized Logging System"""
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
        self.info(f"\\n{sep}\\n{title.center(60)}\\n{sep}")
    
    def log_subsection(self, title):
        self.info(f"\\n{title}\\n{'-'*60}")
    
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
''')
print("✓ Created common/logger.py")

# File 3: common/json_writer.py
with open('common/json_writer.py', 'w') as f:
    f.write('''"""JSON Output Handler"""
import json
import os
from datetime import datetime
from typing import Dict, Any, List

class JSONWriter:
    def __init__(self, output_dir="outputs"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def write_module_output(self, module_name, controls, evidence, target=None, **extra):
        summary = self._calc_summary(controls)
        output = {
            "module": module_name,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "target": target,
            "controls": controls,
            "evidence": evidence,
            "summary": summary
        }
        output.update(extra)
        
        slug = module_name.lower().replace(" ", "_").replace("&", "and")
        filepath = os.path.join(self.output_dir, f"{slug}.json")
        self._write(filepath, output)
        return filepath
    
    def _write(self, path, data):
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def read_json(self, path):
        with open(path) as f:
            return json.load(f)
    
    def merge_outputs(self, files, out="final_report.json"):
        merged = {
            "report_type": "Security GAP Analysis",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "modules": {},
            "overall_summary": {"total_controls":0, "passed":0, "failed":0, "not_tested":0}
        }
        
        for f in files:
            if os.path.exists(f):
                data = self.read_json(f)
                merged["modules"][data.get("module", f)] = data
                s = data.get("summary", {})
                merged["overall_summary"]["total_controls"] += s.get("total", 0)
                merged["overall_summary"]["passed"] += s.get("passed", 0)
                merged["overall_summary"]["failed"] += s.get("failed", 0)
                merged["overall_summary"]["not_tested"] += s.get("not_tested", 0)
        
        total = merged["overall_summary"]["total_controls"]
        if total > 0:
            merged["overall_summary"]["pass_rate"] = round((merged["overall_summary"]["passed"]/total)*100, 2)
        
        path = os.path.join(self.output_dir, out)
        self._write(path, merged)
        return path
    
    def _calc_summary(self, controls):
        return {
            "total": len(controls),
            "passed": sum(1 for v in controls.values() if v.lower() == "pass"),
            "failed": sum(1 for v in controls.values() if v.lower() == "fail"),
            "not_tested": sum(1 for v in controls.values() if v.lower() == "not_tested")
        }

def write_module_output(module_name, controls, evidence, target=None, output_dir="outputs"):
    return JSONWriter(output_dir).write_module_output(module_name, controls, evidence, target)

def merge_outputs(files, output_dir="outputs"):
    return JSONWriter(output_dir).merge_outputs(files)
''')
print("✓ Created common/json_writer.py")

print("\n✅ All common files created successfully!")
print("Next: Run 'python3 create_module1_files.py'")
