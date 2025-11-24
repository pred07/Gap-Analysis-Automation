from unittest.mock import MagicMock

from module2_authentication.discovery import AuthDiscovery
from module2_authentication.controls import (
    run_password_policy,
    run_login_error_messages,
    ControlResult,
)


class DummyResponse:
    def __init__(self, text="", headers=None, status_code=200):
        self.text = text
        self.headers = headers or {"Content-Type": "text/html"}
        self.status_code = status_code


def test_password_policy_detection():
    form = {
        "url": "https://example.com/login",
        "category": "login",
        "inputs": [
            {"name": "username", "type": "text", "label": ""},
            {"name": "password", "type": "password", "label": "Password"},
        ],
    }
    result = run_password_policy([form])
    assert isinstance(result, ControlResult)
    assert result.status in ("fail", "pass")


def test_login_error_message_detection(monkeypatch):
    session = MagicMock()
    session.get.return_value = DummyResponse(text="user does not exist")
    form = {
        "url": "https://example.com/login",
        "method": "GET",
        "inputs": [
            {"name": "user", "type": "text"},
            {"name": "pass", "type": "password"},
        ],
        "category": "login",
    }
    result = run_login_error_messages([form], session, {"username": "admin"}, MagicMock())
    assert result.status == "fail"


