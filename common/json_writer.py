"""JSON Output Handler"""
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
