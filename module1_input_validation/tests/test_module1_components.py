from pathlib import Path
from unittest.mock import MagicMock

from common import load_config
from module1_input_validation.controls import run_sql_injection
from module1_input_validation.directory_scanner import DirectoryScanner
from module1_input_validation.headers_analyzer import HeadersAnalyzer
from module1_input_validation.main import Module1Analyzer


class DummyResponse:
    def __init__(self, text="", headers=None, status_code=200):
        self.text = text
        self.headers = headers or {}
        self.status_code = status_code


def test_headers_analyzer_detects_missing_headers(monkeypatch):
    analyzer = HeadersAnalyzer(logger=MagicMock())

    def fake_get(url, timeout):
        return DummyResponse(headers={"Server": "nginx"})

    monkeypatch.setattr(analyzer.session, "get", fake_get)
    result = analyzer.analyze("https://example.com")
    assert result["missing_headers"], "Expected missing headers to be reported"


def test_directory_scanner_discovers_internal_links(monkeypatch):
    logger = MagicMock()
    scanner = DirectoryScanner(logger, max_depth=1, max_endpoints=5)

    def fake_get(url, timeout):
        html = '<a href="/admin">Admin</a>'
        return DummyResponse(text=html, headers={"Content-Type": "text/html"})

    def fake_head(url, timeout, allow_redirects=True):
        return DummyResponse(headers={"Content-Type": "text/html"}, status_code=200)

    monkeypatch.setattr(scanner.session, "get", fake_get)
    monkeypatch.setattr(scanner.session, "head", fake_head)

    result = scanner.scan("https://example.com")
    assert result["endpoints"], "Expected discovery to return endpoints"


def test_run_sql_injection_detects_error(monkeypatch):
    endpoints = [
        {
            "url": "https://example.com/item",
            "method": "GET",
            "params": ["id"],
            "tags": ["param"],
            "content_type": "text/html",
            "has_file_input": False,
            "form": None,
            "sensitive": False,
        }
    ]

    session = MagicMock()
    session.get.return_value = DummyResponse(text="SQL syntax error near", status_code=500)
    result = run_sql_injection(endpoints, session, MagicMock(), max_payloads=1)
    assert result.status == "fail"
    assert result.findings


def test_module1_loads_targets_from_file(tmp_path):
    config = load_config()
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("https://example.com\nhttps://example.org\n", encoding="utf-8")

    analyzer = Module1Analyzer(config=config, target_file=str(targets_file))
    assert len(analyzer.targets) == 2


