#!/usr/bin/env python3
"""
Batch Orchestrator

Coordinates execution of all 8 security modules with parsed inputs.
Manages module execution, result collection, and error handling.
"""

from __future__ import annotations

import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from common import Config, ModuleResult, load_config
from batch_analysis.document_parser import DocumentParser
from batch_analysis.url_parser import URLParser


logger = logging.getLogger(__name__)


class BatchInputs:
    """Container for batch analysis inputs."""
    
    def __init__(self):
        self.urls: List[str] = []
        self.web_urls: List[str] = []
        self.api_urls: List[str] = []
        self.infrastructure_urls: List[str] = []
        self.controls: List[str] = []
        self.policies: List[str] = []
        self.document_metadata: List[Dict] = []
        self.errors: List[str] = []


class BatchResults:
    """Container for batch analysis results."""
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
        self.module_results: Dict[int, Dict] = {}
        self.summary: Dict[str, Any] = {}
        self.errors: List[str] = []
        self.execution_time: float = 0.0


class BatchOrchestrator:
    """Orchestrate batch execution of all security modules."""
    
    # Module import mapping
    MODULE_IMPORT_MAP = {
        1: ("module1_input_validation.main", "Module1Analyzer"),
        2: ("module2_authentication.main", "Module2Analyzer"),
        3: ("module3_authorization.main", "Module3Analyzer"),
        4: ("module4_sensitive_data.main", "Module4Analyzer"),
        5: ("module5_session_management.main", "Module5Analyzer"),
        6: ("module6_logging_monitoring.main", "Module6Analyzer"),
        7: ("module7_api_security.main", "Module7Analyzer"),
        8: ("module8_infrastructure.main", "Module8Analyzer"),
    }
    
    def __init__(
        self,
        config: Config,
        docs_dir: Optional[Path] = None,
        urls_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        debug: bool = False,
        max_workers: int = 5  # NEW: For parallel processing
    ):
        """
        Initialize batch orchestrator.
        
        Args:
            config: System configuration
            docs_dir: Directory containing documents
            urls_dir: Directory containing URL files
            output_dir: Directory for outputs
            debug: Enable debug logging
            max_workers: Number of parallel workers for URL scanning
        """
        self.config = config
        self.debug = debug
        self.max_workers = max_workers  # NEW
        self.lock = threading.Lock()  # NEW: For thread-safe operations
        
        if debug:
            logger.setLevel(logging.DEBUG)
        
        # Set directories
        self.docs_dir = docs_dir or Path("batch_inputs/documents")
        self.urls_dir = urls_dir or Path("batch_inputs/urls")
        self.output_dir = output_dir or Path("batch_outputs")
        
        # Create output subdirectories
        self.raw_results_dir = self.output_dir / "raw_results"
        self.reports_dir = self.output_dir / "reports"
        self.logs_dir = self.output_dir / "logs"
        
        for directory in [self.raw_results_dir, self.reports_dir, self.logs_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize parsers
        self.doc_parser = DocumentParser(debug=debug)
        self.url_parser = URLParser(debug=debug)
    
    def load_inputs(self) -> BatchInputs:
        """
        Load and parse all inputs.
        
        Returns:
            BatchInputs object with parsed data
        """
        logger.info("Loading batch inputs...")
        inputs = BatchInputs()
        
        # Parse documents
        if self.docs_dir.exists():
            logger.info(f"Parsing documents from {self.docs_dir}...")
            doc_results = self.doc_parser.parse_directory(self.docs_dir)
            inputs.urls.extend(doc_results.get("urls", []))
            inputs.controls = doc_results.get("controls", [])
            inputs.policies = doc_results.get("policies", [])
            inputs.document_metadata = doc_results.get("metadata", [])
            inputs.errors.extend(doc_results.get("errors", []))
        
        # Parse URLs
        if self.urls_dir.exists():
            logger.info(f"Parsing URLs from {self.urls_dir}...")
            url_results = self.url_parser.parse_directory(self.urls_dir)
            inputs.urls.extend(url_results.get("all", []))
            inputs.web_urls = url_results.get("web", [])
            inputs.api_urls = url_results.get("api", [])
            inputs.infrastructure_urls = url_results.get("infrastructure", [])
        
        # Deduplicate URLs
        inputs.urls = list(set(inputs.urls))
        
        logger.info(f"Loaded {len(inputs.urls)} unique URLs")
        logger.info(f"  - Web: {len(inputs.web_urls)}")
        logger.info(f"  - API: {len(inputs.api_urls)}")
        logger.info(f"  - Infrastructure: {len(inputs.infrastructure_urls)}")
        logger.info(f"Found {len(inputs.controls)} controls")
        logger.info(f"Found {len(inputs.policies)} policy references")
        
        return inputs
    
    def execute_all_modules(
        self,
        targets: List[str],
        modules: Optional[List[int]] = None
    ) -> BatchResults:
        """
        Execute all specified modules.
        
        Args:
            targets: List of target URLs
            modules: List of module numbers to run (default: all)
            
        Returns:
            BatchResults object
        """
        start_time = datetime.now()
        results = BatchResults()
        
        if modules is None:
            modules = list(self.MODULE_IMPORT_MAP.keys())
        
        logger.info(f"Executing {len(modules)} modules on {len(targets)} targets...")
        
        for module_num in modules:
            if not self.config.module_enabled(module_num):
                logger.info(f"Module {module_num} disabled in config, skipping")
                continue
            
            logger.info(f"\n{'='*60}")
            logger.info(f"Executing Module {module_num}...")
            logger.info(f"{'='*60}")
            
            try:
                module_result = self.execute_module(module_num, targets)
                results.module_results[module_num] = module_result
                
                # Save individual module result
                self._save_module_result(module_num, module_result)
                
            except Exception as e:
                error_msg = f"Module {module_num} failed: {e}"
                logger.error(error_msg)
                results.errors.append(error_msg)
                results.module_results[module_num] = {
                    "status": "failed",
                    "error": str(e)
                }
        
        # Calculate execution time
        end_time = datetime.now()
        results.execution_time = (end_time - start_time).total_seconds()
        
        # Generate summary
        results.summary = self.generate_summary(results)
        
        logger.info(f"\n{'='*60}")
        logger.info(f"Batch execution completed in {results.execution_time:.2f}s")
        logger.info(f"{'='*60}")
        
        return results
    
    def execute_module(
        self,
        module_num: int,
        targets: List[str]
    ) -> Dict[str, Any]:
        """
        Execute a single module against all targets.
        
        Args:
            module_num: Module number (1-8)
            targets: List of target URLs
            
        Returns:
            Module execution results
        """
        import importlib
        
        module_path, class_name = self.MODULE_IMPORT_MAP[module_num]
        
        try:
            # Import module
            module = importlib.import_module(module_path)
            analyzer_class = getattr(module, class_name)
            
            # If no targets provided, use default
            if not targets:
                targets = [self.config.get_target_url()]
            
            logger.info(f"Scanning {len(targets)} target(s) with Module {module_num} (parallel={self.max_workers > 1})")
            
            # Container for merged results
            merged_targets = []
            merged_summary = {
                "total_controls": 0,
                "passed": 0,
                "failed": 0,
                "not_tested": 0
            }
            last_result = None
            
            # Execute module for each target (PARALLEL if max_workers > 1)
            if self.max_workers > 1 and len(targets) > 1:
                # PARALLEL EXECUTION
                logger.info(f"  Using {self.max_workers} parallel workers")
                
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    # Submit all tasks
                    future_to_target = {
                        executor.submit(self._execute_single_target, analyzer_class, target): target
                        for target in targets
                    }
                    
                    # Collect results as they complete
                    for future in as_completed(future_to_target):
                        target = future_to_target[future]
                        try:
                            result, file_data = future.result()
                            
                            # Thread-safe merge
                            with self.lock:
                                if file_data and "targets" in file_data:
                                    merged_targets.extend(file_data["targets"])
                                
                                if file_data and "summary" in file_data:
                                    s = file_data["summary"]
                                    merged_summary["total_controls"] += s.get("total_controls", 0)
                                    merged_summary["passed"] += s.get("passed", 0)
                                    merged_summary["failed"] += s.get("failed", 0)
                                    merged_summary["not_tested"] += s.get("not_tested", 0)
                                
                                last_result = result
                            
                            logger.info(f"  ✓ Completed {target}")
                        
                        except Exception as e:
                            logger.error(f"  ✗ Failed {target}: {e}")
            
            else:
                # SEQUENTIAL EXECUTION (fallback)
                for target in targets:
                    logger.info(f"  -> Scanning {target}")
                    
                    try:
                        result, file_data = self._execute_single_target(analyzer_class, target)
                        
                        if file_data and "targets" in file_data:
                            merged_targets.extend(file_data["targets"])
                        
                        if file_data and "summary" in file_data:
                            s = file_data["summary"]
                            merged_summary["total_controls"] += s.get("total_controls", 0)
                            merged_summary["passed"] += s.get("passed", 0)
                            merged_summary["failed"] += s.get("failed", 0)
                            merged_summary["not_tested"] += s.get("not_tested", 0)
                        
                        last_result = result
                    
                    except Exception as e:
                        logger.error(f"  ✗ Failed {target}: {e}")


            # Write merged results back to the output file
            if last_result and isinstance(last_result, ModuleResult):
                final_payload = {
                    "module": last_result.module,
                    "module_number": last_result.module_number,
                    "timestamp": datetime.now().isoformat(),
                    "targets": merged_targets,
                    "summary": merged_summary
                }
                
                with open(last_result.output_file, 'w') as f:
                    json.dump(final_payload, f, indent=2)
                
                return {
                    "success": True,
                    "module": last_result.module,
                    "module_number": last_result.module_number,
                    "output_file": last_result.output_file,
                    "timestamp": datetime.now().isoformat(),
                    "targets": merged_targets,  # Include for immediate use
                    "summary": merged_summary
                }
            
            return {"success": False, "error": "No valid results generated"}
            
        except Exception as e:
            logger.error(f"Error executing module {module_num}: {e}")
            raise
    
    def _execute_single_target(self, analyzer_class, target: str):
        """
        Execute module for a single target (thread-safe helper).
        
        Args:
            analyzer_class: Module analyzer class
            target: Target URL
        
        Returns:
            Tuple of (result, file_data)
        """
        # Instantiate analyzer for this target
        analyzer = analyzer_class(
            config=self.config,
            target=target,
            debug=self.debug
        )
        
        # Execute
        result = analyzer.execute()
        
        # Read output file
        file_data = None
        if isinstance(result, ModuleResult):
            try:
                with open(result.output_file, 'r') as f:
                    file_data = json.load(f)
            except Exception as e:
                logger.warning(f"Could not read result file for {target}: {e}")
        
        return result, file_data
    
    def generate_summary(self, results: BatchResults) -> Dict[str, Any]:
        """
        Generate summary statistics.
        
        Args:
            results: Batch results
            
        Returns:
            Summary dictionary
        """
        summary = {
            "total_modules": len(results.module_results),
            "successful_modules": 0,
            "failed_modules": 0,
            "total_controls": 65,
            "controls_passed": 0,
            "controls_failed": 0,
            "controls_not_tested": 0,
            "execution_time": results.execution_time,
            "timestamp": results.timestamp
        }
        
        # Count successes/failures
        for module_result in results.module_results.values():
            if module_result.get("success", False):
                summary["successful_modules"] += 1
            else:
                summary["failed_modules"] += 1
        
        # TODO: Parse individual module results to count control statuses
        # This will be implemented when we integrate with actual module outputs
        
        return summary
    
    def _save_module_result(self, module_num: int, result: Dict[str, Any]):
        """Save individual module result to file."""
        output_file = self.raw_results_dir / f"module{module_num}_result.json"
        
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        logger.info(f"Saved module {module_num} result to {output_file}")
    
    def save_batch_results(self, results: BatchResults) -> Path:
        """
        Save complete batch results.
        
        Args:
            results: Batch results to save
            
        Returns:
            Path to saved results file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.raw_results_dir / f"batch_results_{timestamp}.json"
        
        # Convert to dict
        results_dict = {
            "timestamp": results.timestamp,
            "execution_time": results.execution_time,
            "summary": results.summary,
            "module_results": results.module_results,
            "errors": results.errors
        }
        
        with open(output_file, 'w') as f:
            json.dump(results_dict, f, indent=2)
        
        logger.info(f"Saved batch results to {output_file}")
        return output_file


if __name__ == "__main__":
    # Test the orchestrator
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Load config
    config = load_config("config")
    
    # Create orchestrator
    orchestrator = BatchOrchestrator(
        config=config,
        debug=True
    )
    
    # Load inputs
    inputs = orchestrator.load_inputs()
    
    print("\n=== Batch Orchestrator Test ===")
    print(f"Total URLs: {len(inputs.urls)}")
    print(f"Controls: {len(inputs.controls)}")
    print(f"Policies: {len(inputs.policies)}")
    print(f"Errors: {len(inputs.errors)}")
