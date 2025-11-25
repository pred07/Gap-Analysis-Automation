"""
Unit tests for Module 8 components.
"""

from unittest.mock import MagicMock

from module8_infrastructure.controls import (
    ControlResult,
    run_container_security,
    run_host_hardening,
    run_least_privilege,
    run_security_updates,
)


def test_host_hardening_pass():
    """Test host hardening with evidence in documents."""
    documents = [
        {
            "name": "security_policy.txt",
            "content": "All servers follow CIS benchmarks and Lynis hardening guidelines"
        }
    ]
    logger = MagicMock()
    
    result = run_host_hardening(documents, logger)
    
    assert isinstance(result, ControlResult)
    assert result.name == "Host_Hardening"
    assert result.status == "pass"


def test_host_hardening_fail():
    """Test host hardening without evidence."""
    documents = [
        {
            "name": "readme.txt",
            "content": "This is a simple application"
        }
    ]
    logger = MagicMock()
    
    result = run_host_hardening(documents, logger)
    
    assert result.status == "fail"


def test_container_security_pass():
    """Test container security with scanning evidence."""
    documents = [
        {
            "name": "container_policy.md",
            "content": "All container images are scanned with Trivy before deployment"
        }
    ]
    logger = MagicMock()
    
    result = run_container_security(documents, logger)
    
    assert result.status == "pass"


def test_least_privilege_pass():
    """Test least privilege with RBAC evidence."""
    documents = [
        {
            "name": "access_control.txt",
            "content": "RBAC policies enforce least privilege principle for all services"
        }
    ]
    logger = MagicMock()
    
    result = run_least_privilege(documents, logger)
    
    assert result.status == "pass"


def test_security_updates_pass():
    """Test security updates with patch management policy."""
    documents = [
        {
            "name": "patch_policy.txt",
            "content": "Security updates are applied within 7 days of release"
        }
    ]
    logger = MagicMock()
    
    result = run_security_updates(documents, logger)
    
    assert result.status == "pass"


def test_no_documents():
    """Test with no documents provided."""
    documents = []
    logger = MagicMock()
    
    result = run_host_hardening(documents, logger)
    
    assert result.status == "not_tested"
