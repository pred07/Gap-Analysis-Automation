"""
Unit tests for Module 4 components.
"""

from unittest.mock import MagicMock

from module4_sensitive_data.controls import (
    ControlResult,
    run_clear_text_detection,
    run_https_tls,
    run_password_encryption_rest,
    run_pci_pan_masking,
    run_sensitive_data_masking,
)


def test_https_tls_pass():
    """Test HTTPS/TLS control with valid configuration."""
    target = "https://example.com"
    tls_results = {
        "success": True,
        "tls_version": "TLS 1.2",
        "cert_valid": True,
    }
    logger = MagicMock()
    
    result = run_https_tls(target, tls_results, logger)
    
    assert isinstance(result, ControlResult)
    assert result.name == "HTTPS_TLS"
    assert result.status == "pass"
    assert len(result.findings) == 0


def test_https_tls_fail_http():
    """Test HTTPS/TLS control with HTTP target."""
    target = "http://example.com"
    tls_results = {}
    logger = MagicMock()
    
    result = run_https_tls(target, tls_results, logger)
    
    assert result.status == "fail"
    assert len(result.findings) > 0
    assert result.findings[0]["indicator"] == "http_not_https"


def test_sensitive_data_masking_pass():
    """Test sensitive data masking with clean pages."""
    pages = [
        {"url": "https://example.com", "content": "Welcome to our site"},
        {"url": "https://example.com/about", "content": "About us page"},
    ]
    logger = MagicMock()
    
    result = run_sensitive_data_masking(pages, logger)
    
    assert result.status == "pass"
    assert len(result.findings) == 0


def test_sensitive_data_masking_fail():
    """Test sensitive data masking with exposed credit card."""
    pages = [
        {
            "url": "https://example.com/checkout",
            "content": "Your card: 4111-1111-1111-1111",
        }
    ]
    logger = MagicMock()
    
    result = run_sensitive_data_masking(pages, logger)
    
    assert result.status == "fail"
    assert len(result.findings) > 0


def test_password_encryption_rest_pass():
    """Test password encryption at rest with strong hashing."""
    documents = [
        {
            "name": "security_policy.txt",
            "content": "Passwords are hashed using bcrypt with salt",
        }
    ]
    logger = MagicMock()
    
    result = run_password_encryption_rest(documents, logger)
    
    assert result.status == "pass"


def test_password_encryption_rest_fail():
    """Test password encryption at rest with weak hashing."""
    documents = [
        {
            "name": "old_policy.txt",
            "content": "Passwords stored using MD5 hash",
        }
    ]
    logger = MagicMock()
    
    result = run_password_encryption_rest(documents, logger)
    
    assert result.status == "fail"
    assert len(result.findings) > 0


def test_pci_pan_masking_pass():
    """Test PCI PAN masking with properly masked cards."""
    pages = [
        {
            "url": "https://example.com/account",
            "content": "Card ending in ****1234",
        }
    ]
    documents = []
    logger = MagicMock()
    
    result = run_pci_pan_masking(pages, documents, logger)
    
    assert result.status == "pass"


def test_pci_pan_masking_fail():
    """Test PCI PAN masking with unmasked PAN."""
    pages = [
        {
            "url": "https://example.com/admin",
            "content": "Customer card: 4111-1111-1111-1111",
        }
    ]
    documents = []
    logger = MagicMock()
    
    result = run_pci_pan_masking(pages, documents, logger)
    
    assert result.status == "fail"
    assert len(result.findings) > 0


def test_clear_text_detection_pass():
    """Test clear-text detection with secure pages."""
    pages = [
        {"url": "https://example.com", "content": "Secure login page"},
    ]
    logger = MagicMock()
    
    result = run_clear_text_detection(pages, logger)
    
    assert result.status == "pass"


def test_clear_text_detection_fail():
    """Test clear-text detection with exposed password."""
    pages = [
        {
            "url": "https://example.com/debug",
            "content": "password: SuperSecret123",
        }
    ]
    logger = MagicMock()
    
    result = run_clear_text_detection(pages, logger)
    
    assert result.status == "fail"
    assert len(result.findings) > 0
