"""
Unit tests for Module 5 components.
"""

from unittest.mock import MagicMock

from module5_session_management.controls import (
    ControlResult,
    run_cookie_flags,
    run_session_id_randomness,
    run_session_not_in_url,
    run_server_side_validation,
)


def test_session_not_in_url_pass():
    """Test session not in URL control with clean URLs."""
    pages = [
        {"url": "https://example.com/page1"},
        {"url": "https://example.com/page2"},
    ]
    logger = MagicMock()
    
    result = run_session_not_in_url(pages, logger)
    
    assert isinstance(result, ControlResult)
    assert result.name == "Session_Not_In_URL"
    assert result.status == "pass"
    assert len(result.findings) == 0


def test_session_not_in_url_fail():
    """Test session not in URL control with session in URL."""
    pages = [
        {"url": "https://example.com/page?session=abc123"},
    ]
    logger = MagicMock()
    
    result = run_session_not_in_url(pages, logger)
    
    assert result.status == "fail"
    assert len(result.findings) > 0
    assert result.findings[0]["indicator"] == "session_in_url"


def test_session_id_randomness_weak():
    """Test session ID randomness with weak session ID."""
    pages = [{"url": "https://example.com"}]
    
    # Mock session factory that returns session with weak cookie
    def mock_session_factory():
        session = MagicMock()
        mock_response = MagicMock()
        mock_cookie = MagicMock()
        mock_cookie.name = "sessionid"
        mock_cookie.value = "12345"  # Weak: too short and numeric
        mock_response.cookies = [mock_cookie]
        session.get.return_value = mock_response
        return session
    
    logger = MagicMock()
    
    result = run_session_id_randomness(pages, mock_session_factory, logger)
    
    assert result.status == "fail"
    assert len(result.findings) > 0


def test_server_side_validation_pass():
    """Test server-side validation with proper access control."""
    pages = [
        {"url": "https://example.com/admin/dashboard"},
    ]
    
    # Mock session factory that returns 401/403 for protected pages
    def mock_session_factory():
        session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        session.get.return_value = mock_response
        return session
    
    logger = MagicMock()
    
    result = run_server_side_validation(pages, mock_session_factory, logger)
    
    assert result.status == "pass"


def test_server_side_validation_fail():
    """Test server-side validation with accessible protected page."""
    pages = [
        {"url": "https://example.com/admin/dashboard"},
    ]
    
    # Mock session factory that returns 200 OK for protected pages
    def mock_session_factory():
        session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Welcome to admin dashboard"
        session.get.return_value = mock_response
        return session
    
    logger = MagicMock()
    
    result = run_server_side_validation(pages, mock_session_factory, logger)
    
    assert result.status == "fail"
    assert len(result.findings) > 0
