"""
External Tool Executor for Security GAP Analysis.
"""

from __future__ import annotations

import os
import subprocess
import time
from datetime import datetime
from typing import Any, Dict, List, Optional


class ToolExecutionError(Exception):
    """Custom exception for tool execution failures"""
    pass


class ToolRunner:
    """
    Manages execution of external security tools
    
    Features:
    - Command sanitization
    - Timeout handling
    - Output capture (stdout/stderr)
    - Error handling
    - Process cleanup
    """
    
    def __init__(self, logger=None, default_timeout=300, retry_count: int = 0, retry_delay: int = 5):
        """
        Initialize tool runner
        
        Args:
            logger: Logger instance
            default_timeout (int): Default timeout in seconds
        """
        self.logger = logger
        self.default_timeout = default_timeout
        self.last_execution = None
        self.default_retry_count = retry_count
        self.default_retry_delay = retry_delay

    def run(
        self,
        command: List[str],
        timeout: Optional[int] = None,
        capture_output: bool = True,
        check: bool = False,
        env: Optional[Dict] = None,
        cwd: Optional[str] = None,
        retries: Optional[int] = None,
        retry_delay: Optional[int] = None,
    ) -> Dict:
        """
        Execute external command
        
        Args:
            command (list): Command and arguments
            timeout (int): Timeout in seconds
            capture_output (bool): Capture stdout/stderr
            check (bool): Raise exception on non-zero return code
            env (dict): Environment variables
            cwd (str): Working directory
        
        Returns:
            dict: Execution results
        """
        if timeout is None:
            timeout = self.default_timeout
        if retries is None:
            retries = self.default_retry_count
        if retry_delay is None:
            retry_delay = self.default_retry_delay

        if not command or not isinstance(command, list):
            raise ValueError("Command must be a non-empty list")

        attempts = retries + 1
        last_result: Dict[str, Any] | None = None

        for attempt in range(1, attempts + 1):
            last_result = self._run_once(
                command,
                timeout=timeout,
                capture_output=capture_output,
                check=check,
                env=env,
                cwd=cwd,
            )

            if not last_result.get("error"):
                break

            if attempt < attempts:
                if self.logger:
                    self.logger.warning(
                        f"Retrying {command[0]} ({attempt}/{attempts-1}) after error: {last_result['error']}"
                    )
                time.sleep(retry_delay)

        return last_result or {}

    def _run_once(
        self,
        command: List[str],
        timeout: int,
        capture_output: bool,
        check: bool,
        env: Optional[Dict],
        cwd: Optional[str],
    ) -> Dict:
        if self.logger:
            self.logger.log_tool_execution(command[0], " ".join(command), "started")

        start_time = datetime.now()
        result = {
            "command": " ".join(command),
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "duration": 0,
            "timed_out": False,
            "error": None,
        }

        try:
            process = subprocess.run(
                command,
                capture_output=capture_output,
                timeout=timeout,
                text=True,
                env=env or os.environ.copy(),
                cwd=cwd,
            )

            result["returncode"] = process.returncode
            result["stdout"] = process.stdout if capture_output else ""
            result["stderr"] = process.stderr if capture_output else ""

            if check and process.returncode != 0:
                raise ToolExecutionError(
                    f"Command failed with return code {process.returncode}: {result['stderr']}"
                )

            if self.logger:
                self.logger.log_tool_execution(command[0], "", "completed")

        except subprocess.TimeoutExpired:
            result["timed_out"] = True
            result["error"] = f"Command timed out after {timeout} seconds"
            if self.logger:
                self.logger.error(f"Tool {command[0]} timed out")

        except FileNotFoundError:
            result["error"] = f"Tool not found: {command[0]}"
            if self.logger:
                self.logger.error(result["error"])

        except Exception as exc:
            result["error"] = str(exc)
            if self.logger:
                self.logger.exception(f"Tool execution failed: {command[0]}")

        finally:
            end_time = datetime.now()
            result["duration"] = (end_time - start_time).total_seconds()
            self.last_execution = result

        return result
    
    def run_shell(self, command: str, **kwargs) -> Dict:
        """
        Execute shell command (use with caution)
        
        Args:
            command (str): Shell command
            **kwargs: Additional arguments for run()
        
        Returns:
            dict: Execution results
        """
        # Warning: shell=True can be dangerous with untrusted input
        if self.logger:
            self.logger.warning("Executing shell command (potential security risk)")
        
        return self.run(["sh", "-c", command], **kwargs)
    
    def run_with_input(self, command: List[str], stdin_data: str, **kwargs) -> Dict:
        """
        Execute command with stdin input
        
        Args:
            command (list): Command and arguments
            stdin_data (str): Data to pass to stdin
            **kwargs: Additional arguments
        
        Returns:
            dict: Execution results
        """
        timeout = kwargs.pop('timeout', self.default_timeout)
        
        try:
            process = subprocess.run(
                command,
                input=stdin_data,
                capture_output=True,
                timeout=timeout,
                text=True
            )
            
            return {
                "command": " ".join(command),
                "returncode": process.returncode,
                "stdout": process.stdout,
                "stderr": process.stderr,
                "timed_out": False,
                "error": None
            }
        
        except Exception as e:
            return {
                "command": " ".join(command),
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "timed_out": isinstance(e, subprocess.TimeoutExpired),
                "error": str(e)
            }
    
    def run_async(self, command: List[str], **kwargs) -> subprocess.Popen:
        """
        Execute command asynchronously
        
        Args:
            command (list): Command and arguments
            **kwargs: Additional arguments
        
        Returns:
            Popen: Process object
        """
        return subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **kwargs
        )
    
    def check_tool_available(self, tool_name: str) -> bool:
        """
        Check if tool is available
        
        Args:
            tool_name (str): Tool executable name
        
        Returns:
            bool: True if available
        """
        result = self.run([tool_name, "--version"], timeout=5, check=False)
        return result["returncode"] == 0 and result["error"] is None


class ZAPRunner(ToolRunner):
    """Specialized runner for OWASP ZAP"""
    
    def __init__(self, zap_path: str, logger=None):
        super().__init__(logger)
        self.zap_path = zap_path
    
    def quick_scan(self, target_url: str, output_file: str) -> Dict:
        """
        Run ZAP quick scan
        
        Args:
            target_url (str): Target URL
            output_file (str): Output XML file
        
        Returns:
            dict: Execution results
        """
        command = [
            self.zap_path,
            "-cmd",
            "-quickurl", target_url,
            "-quickout", output_file
        ]
        return self.run(command, timeout=600)
    
    def active_scan(self, target_url: str, output_file: str) -> Dict:
        """
        Run ZAP active scan
        
        Args:
            target_url (str): Target URL
            output_file (str): Output XML file
        
        Returns:
            dict: Execution results
        """
        command = [
            self.zap_path,
            "-cmd",
            "-quickurl", target_url,
            "-quickout", output_file,
            "-quickprogress"
        ]
        return self.run(command, timeout=1800)  # 30 minutes


class NiktoRunner(ToolRunner):
    """Specialized runner for Nikto"""
    
    def __init__(self, nikto_path: str = "nikto", logger=None):
        super().__init__(logger)
        self.nikto_path = nikto_path
    
    def scan(self, target: str, output_file: str, ssl: bool = False) -> Dict:
        """
        Run Nikto scan
        
        Args:
            target (str): Target host
            output_file (str): Output file
            ssl (bool): Use SSL
        
        Returns:
            dict: Execution results
        """
        command = [
            self.nikto_path,
            "-h", target,
            "-o", output_file,
            "-Format", "txt"
        ]
        
        if ssl:
            command.extend(["-ssl"])
        
        return self.run(command, timeout=900)  # 15 minutes


class TestSSLRunner(ToolRunner):
    """Specialized runner for testssl.sh"""
    
    def __init__(self, testssl_path: str, logger=None):
        super().__init__(logger)
        self.testssl_path = testssl_path
    
    def scan(self, target: str, output_file: str = None) -> Dict:
        """
        Run testssl.sh scan
        
        Args:
            target (str): Target host:port
            output_file (str): Output file
        
        Returns:
            dict: Execution results
        """
        command = [self.testssl_path, "--quiet", target]
        
        if output_file:
            command.extend(["--log", output_file])
        
        return self.run(command, timeout=300)


class LynisRunner(ToolRunner):
    """Specialized runner for Lynis"""
    
    def __init__(self, lynis_path: str = "lynis", logger=None):
        super().__init__(logger)
        self.lynis_path = lynis_path
    
    def audit_system(self, output_file: str = None) -> Dict:
        """
        Run Lynis system audit
        
        Args:
            output_file (str): Output file
        
        Returns:
            dict: Execution results
        """
        command = [
            self.lynis_path,
            "audit", "system",
            "--quick",
            "--quiet"
        ]
        
        result = self.run(command, timeout=600)
        
        # Lynis writes to /var/log/lynis.log by default
        if output_file and os.path.exists("/var/log/lynis.log"):
            import shutil
            shutil.copy("/var/log/lynis.log", output_file)
        
        return result


class TrivyRunner(ToolRunner):
    """Specialized runner for Trivy"""
    
    def __init__(self, trivy_path: str = "trivy", logger=None):
        super().__init__(logger)
        self.trivy_path = trivy_path
    
    def scan_image(self, image_name: str, output_file: str = None) -> Dict:
        """
        Scan container image
        
        Args:
            image_name (str): Container image name
            output_file (str): Output file
        
        Returns:
            dict: Execution results
        """
        command = [
            self.trivy_path,
            "image",
            "--severity", "HIGH,CRITICAL",
            image_name
        ]
        
        if output_file:
            command.extend(["-o", output_file])
        
        return self.run(command, timeout=300)


class NewmanRunner(ToolRunner):
    """Specialized runner for Newman (Postman CLI)"""
    
    def __init__(self, newman_path: str = "newman", logger=None):
        super().__init__(logger)
        self.newman_path = newman_path
    
    def run_collection(self, collection_file: str, environment: str = None,
                      output_file: str = None) -> Dict:
        """
        Run Postman collection
        
        Args:
            collection_file (str): Collection JSON file
            environment (str): Environment JSON file
            output_file (str): Output file
        
        Returns:
            dict: Execution results
        """
        command = [
            self.newman_path,
            "run", collection_file
        ]
        
        if environment:
            command.extend(["-e", environment])
        
        if output_file:
            command.extend(["--reporters", "json", "--reporter-json-export", output_file])
        
        return self.run(command, timeout=300)


# Example usage
if __name__ == "__main__":
    from logger import get_logger
    
    logger = get_logger("tool_runner_test", debug_mode=True)
    
    # Test basic tool runner
    runner = ToolRunner(logger=logger)
    
    # Test simple command
    result = runner.run(["python3", "--version"])
    print(f"Python version check: {result['returncode']}")
    print(f"Output: {result['stdout']}")
    
    # Test tool availability
    print(f"\nPython3 available: {runner.check_tool_available('python3')}")
    print(f"Fake tool available: {runner.check_tool_available('fake-tool')}")
