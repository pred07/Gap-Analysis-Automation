"""
Unit tests for Module 7 components.
"""

from unittest.mock import MagicMock

from module7_api_security.controls import (
    ControlResult,
    run_api_cors_configuration,
    run_api_rate_limiting,
    run_api_sensitive_params,
    run_api_versioning,
)


def test_api_versioning_pass():
    """Test API versioning with versioned endpoints."""
    api_endpoints = [
        "https://api.example.com/v1/users",
        "https://api.example.com/v1/posts",
    ]
    logger = MagicMock()
    
    result = run_api_versioning(api_endpoints, logger)
    
    assert isinstance(result, ControlResult)
    assert result.name == "API_Versioning"
    assert result.status == "pass"


def test_api_versioning_fail():
    """Test API versioning without version indicators."""
    api_endpoints = [
        "https://api.example.com/users",
        "https://api.example.com/posts",
    ]
    logger = MagicMock()
    
    result = run_api_versioning(api_endpoints, logger)
    
    assert result.status == "fail"


def test_api_sensitive_params_pass():
    """Test API sensitive params with clean URLs."""
    api_endpoints = [
        "https://api.example.com/v1/users",
    ]
    logger = MagicMock()
    
    result = run_api_sensitive_params(api_endpoints, MagicMock(), logger)
    
    assert result.status == "pass"


def test_api_sensitive_params_fail():
    """Test API sensitive params with password in URL."""
    api_endpoints = [
        "https://api.example.com/login?password=secret123",
    ]
    logger = MagicMock()
    
    result = run_api_sensitive_params(api_endpoints, MagicMock(), logger)
    
    assert result.status == "fail"
    assert len(result.findings) > 0
