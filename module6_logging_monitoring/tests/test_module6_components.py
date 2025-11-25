"""
Unit tests for Module 6 components.
"""

from unittest.mock import MagicMock

from module6_logging_monitoring.controls import (
    ControlResult,
    run_access_logging,
    run_authentication_logging,
    run_error_logging,
    run_security_event_logging,
)


def test_authentication_logging_pass():
    """Test authentication logging with auth events in logs."""
    log_files = [
        {
            "name": "app.log",
            "content": "2025-11-25 09:00:00 [INFO] User 'admin' logged in successfully"
        }
    ]
    logger = MagicMock()
    
    result = run_authentication_logging(log_files, logger)
    
    assert isinstance(result, ControlResult)
    assert result.name == "Authentication_Logging"
    assert result.status == "pass"
    assert len(result.findings) == 0


def test_authentication_logging_fail():
    """Test authentication logging without auth events."""
    log_files = [
        {
            "name": "app.log",
            "content": "2025-11-25 09:00:00 [INFO] Application started"
        }
    ]
    logger = MagicMock()
    
    result = run_authentication_logging(log_files, logger)
    
    assert result.status == "fail"
    assert len(result.findings) > 0


def test_access_logging_pass():
    """Test access logging with HTTP access logs."""
    log_files = [
        {
            "name": "access.log",
            "content": "192.168.1.100 - - [25/Nov/2025:09:00:00] GET /api/users 200"
        }
    ]
    logger = MagicMock()
    
    result = run_access_logging(log_files, logger)
    
    assert result.status == "pass"


def test_error_logging_pass():
    """Test error logging with error events."""
    log_files = [
        {
            "name": "error.log",
            "content": "2025-11-25 09:00:00 [ERROR] Database connection failed"
        }
    ]
    logger = MagicMock()
    
    result = run_error_logging(log_files, logger)
    
    assert result.status == "pass"


def test_security_event_logging_pass():
    """Test security event logging with security events."""
    log_files = [
        {
            "name": "security.log",
            "content": "2025-11-25 09:00:00 [WARN] Possible SQL injection attack detected"
        }
    ]
    logger = MagicMock()
    
    result = run_security_event_logging(log_files, logger)
    
    assert result.status == "pass"


def test_no_log_files():
    """Test with no log files provided."""
    log_files = []
    logger = MagicMock()
    
    result = run_authentication_logging(log_files, logger)
    
    assert result.status == "not_tested"
