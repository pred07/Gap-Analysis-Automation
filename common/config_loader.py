"""
Configuration Loader for Security GAP Analysis
Handles loading and validation of YAML configuration files
"""

import yaml
import os
from typing import Dict, Any, Optional
from pathlib import Path


class ConfigurationError(Exception):
    """Custom exception for configuration errors"""
    pass


class Config:
    """
    Configuration manager for the security assessment framework
    
    Loads and provides access to:
    - Global configuration (config.yaml)
    - Tool paths (tool_paths.yaml)
    - Control mappings (control_mapping.yaml)
    """
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize configuration loader
        
        Args:
            config_dir (str): Path to config directory
        """
        self.config_dir = Path(config_dir)
        self._config = {}
        self._tool_paths = {}
        self._control_mapping = {}
        
        # Load all configurations
        self._load_all()
    
    def _load_all(self):
        """Load all configuration files"""
        try:
            self._config = self._load_yaml("config.yaml")
            self._tool_paths = self._load_yaml("tool_paths.yaml")
            self._control_mapping = self._load_yaml("control_mapping.yaml")
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    def _load_yaml(self, filename: str) -> Dict[str, Any]:
        """
        Load YAML file
        
        Args:
            filename (str): YAML filename
        
        Returns:
            dict: Parsed YAML data
        """
        filepath = self.config_dir / filename
        
        if not filepath.exists():
            # Return empty dict if file doesn't exist
            return {}
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                return data if data is not None else {}
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Error parsing {filename}: {e}")
    
    # Global Configuration Methods
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value
        
        Args:
            key (str): Configuration key (supports dot notation: 'target.url')
            default: Default value if key not found
        
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_target_url(self) -> Optional[str]:
        """Get target URL"""
        return self.get('target.url')
    
    def get_target_api(self) -> Optional[str]:
        """Get target API base URL"""
        return self.get('target.api_base')
    
    def get_credentials(self) -> Dict[str, str]:
        """Get test credentials"""
        return self.get('credentials', {})
    
    def get_documents(self) -> list:
        """Get list of documents to analyze"""
        return self.get('documents', [])
    
    def get_output_dir(self) -> str:
        """Get output directory"""
        return self.get('output.directory', 'outputs')
    
    def get_log_level(self) -> str:
        """Get log level"""
        return self.get('output.log_level', 'INFO')
    
    def is_parallel_execution(self) -> bool:
        """Check if parallel execution is enabled"""
        return self.get('execution.parallel', False)
    
    def get_timeout(self) -> int:
        """Get module execution timeout"""
        return self.get('execution.timeout', 300)
    
    def get_retry_count(self) -> int:
        """Get retry count for failed operations"""
        return self.get('execution.retry_count', 2)
    
    # Tool Paths Methods
    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """
        Get path to security tool
        
        Args:
            tool_name (str): Tool name (e.g., 'zap', 'nikto')
        
        Returns:
            str: Tool path or None
        """
        return self._tool_paths.get('tools', {}).get(tool_name)
    
    def get_all_tool_paths(self) -> Dict[str, str]:
        """Get all tool paths"""
        return self._tool_paths.get('tools', {})
    
    # Control Mapping Methods
    def get_module_controls(self, module_number: int) -> list:
        """
        Get controls for a specific module
        
        Args:
            module_number (int): Module number (1-8)
        
        Returns:
            list: List of control dictionaries
        """
        module_key = f"module{module_number}"
        return self._control_mapping.get('modules', {}).get(module_key, {}).get('controls', [])
    
    def get_module_info(self, module_number: int) -> Dict[str, Any]:
        """
        Get complete module information
        
        Args:
            module_number (int): Module number (1-8)
        
        Returns:
            dict: Module information
        """
        module_key = f"module{module_number}"
        return self._control_mapping.get('modules', {}).get(module_key, {})
    
    def get_control_by_id(self, control_id: str) -> Optional[Dict]:
        """
        Get control information by ID
        
        Args:
            control_id (str): Control ID
        
        Returns:
            dict: Control information or None
        """
        for module in self._control_mapping.get('modules', {}).values():
            for control in module.get('controls', []):
                if control.get('id') == control_id:
                    return control
        return None
    
    def get_all_controls(self) -> list:
        """Get all 65 controls"""
        all_controls = []
        for module in self._control_mapping.get('modules', {}).values():
            all_controls.extend(module.get('controls', []))
        return all_controls
    
    def get_total_controls_count(self) -> int:
        """Get total number of controls"""
        return len(self.get_all_controls())
    
    # Validation Methods
    def validate(self) -> Dict[str, list]:
        """
        Validate configuration
        
        Returns:
            dict: Validation results with errors and warnings
        """
        errors = []
        warnings = []
        
        # Check required configurations
        if not self.get_target_url() and not self.get_target_api():
            errors.append("No target URL or API configured")
        
        # Check tool paths
        tools = self.get_all_tool_paths()
        if not tools:
            warnings.append("No tool paths configured")
        
        # Check control mappings
        if self.get_total_controls_count() != 65:
            warnings.append(f"Expected 65 controls, found {self.get_total_controls_count()}")
        
        # Check output directory
        output_dir = self.get_output_dir()
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create output directory: {e}")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }
    
    def __repr__(self) -> str:
        """String representation"""
        return f"Config(target={self.get_target_url()}, controls={self.get_total_controls_count()})"


def load_config(config_dir: str = "config") -> Config:
    """
    Factory function to load configuration
    
    Args:
        config_dir (str): Path to config directory
    
    Returns:
        Config: Configuration instance
    """
    return Config(config_dir)


# Example usage
if __name__ == "__main__":
    print("=== Configuration Loader Test ===\n")
    
    try:
        config = load_config()
        
        print("Target Configuration:")
        print(f"  URL: {config.get_target_url()}")
        print(f"  API: {config.get_target_api()}")
        
        print("\nExecution Settings:")
        print(f"  Parallel: {config.is_parallel_execution()}")
        print(f"  Timeout: {config.get_timeout()}s")
        print(f"  Retry: {config.get_retry_count()}")
        
        print("\nTool Paths:")
        for tool, path in config.get_all_tool_paths().items():
            print(f"  {tool}: {path}")
        
        print("\nControl Mapping:")
        print(f"  Total Controls: {config.get_total_controls_count()}")
        
        print("\nModule 1 Info:")
        module1 = config.get_module_info(1)
        print(f"  Name: {module1.get('name')}")
        print(f"  Description: {module1.get('description')}")
        print(f"  Controls: {len(module1.get('controls', []))}")
        
        print("\nValidation:")
        validation = config.validate()
        print(f"  Valid: {validation['valid']}")
        if validation['errors']:
            print("  Errors:")
            for error in validation['errors']:
                print(f"    - {error}")
        if validation['warnings']:
            print("  Warnings:")
            for warning in validation['warnings']:
                print(f"    - {warning}")
    
    except ConfigurationError as e:
        print(f"Configuration Error: {e}")
