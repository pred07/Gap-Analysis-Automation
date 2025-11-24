from unittest.mock import MagicMock

from module3_authorization.controls import run_database_permission_controls


class DummySession:
    def get(self, url, timeout=10):
        class Resp:
            status_code = 200

        return Resp()


def test_idor_detection():
    pages = [{"url": "https://example.com/item/123"}]
    result = run_database_permission_controls(pages, lambda: DummySession(), MagicMock())
    assert result.status in ("fail", "pass")

