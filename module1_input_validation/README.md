# Module 1: Input & Data Validation Analyzer

Module 1 ingests one or more base URLs, performs automatic crawling + smart wordlist probing, classifies every discovered endpoint, and runs the full OWASP-style input & data validation control suite (10 controls). Optional integrations with OWASP ZAP and Nikto can enrich evidence when configured.

## Controls Covered

| ID  | Control | Source |
| --- | --- | --- |
| 001 | SQL_Injection | Automated payload fuzzing across all param endpoints |
| 002 | XSS | Reflective XSS probes with multiple payloads |
| 003 | HTTP_Request_Smuggling | Lightweight CL.TE / TE.CL probe |
| 004 | Client_Side_Validation | Form heuristics + invalid input replay |
| 005 | File_Upload | Automated safe vs. dangerous upload attempts |
| 006 | XML_Validation | XXE-style XML payload checks |
| 007 | Schema_Validation | Invalid JSON schema submissions |
| 008 | Content_Type | Mismatch detection across responses |
| 009 | Buffer_Overflow_Basic | Oversized payload stress on parameters |
| 010 | DOS_Basic | Configurable low-volume burst testing (disabled by default) |

## Workflow

1. **Target ingestion** – single `--target` or newline-delimited `--target-file`.
2. **Smart discovery** – depth-limited BFS + optional wordlist probing, parsing links, forms, scripts, uploads, JSON/XML APIs.
3. **Classification** – every endpoint tagged (HTML, upload, param, json, xml, api) with supporting metadata.
4. **Control execution** – each control module uses the classified endpoints (SQLi, XSS, smuggling, upload, XML, schema, etc.).
5. **Optional tooling** – OWASP ZAP / Nikto via `common.tool_runner` if enabled.
6. **Evidence packaging** – per-target findings, endpoint catalog, and reports are written to a single `targets[]` JSON output.

## Usage

### Run via orchestrator

```bash
python3 run_module.py --module=1 \
  --target=https://target.local \
  --enable-zap \
  --enable-nikto \
  --depth=3 \
  --debug
```

### Standalone execution

```bash
python3 module1_input_validation/main.py \
  --target-file targets.txt \
  --max-endpoints 50 \
  --depth 3
```

- `--target` – single URL override.
- `--target-file` – newline-delimited URL list (can be combined with `--target`).
- `--depth` – recursion depth for crawler.
- `--max-endpoints` – fuzzing limit per target.
- `--enable-zap/--enable-nikto` – trigger external tool runners when configured.

## Output

- JSON file (slugged as `input_and_data_validation.json`) with structure:
  - `targets[]`: per-base-URL records
    - `controls`: map of the 10 control statuses (`pass` / `fail` / `not_tested`)
    - `evidence.endpoints`: classified endpoint catalog (URL, method, tags, params, upload/file info)
    - `evidence.findings`: detailed findings per control (payload, indicator, response codes)
    - `evidence.reports`: tool outputs (ZAP/Nikto) when run
    - `summary`: counts of pass/fail/not_tested for that target
  - `summary`: overall totals across all targets
- Output is validated against `common.schema_validator.MODULE_OUTPUT_SCHEMA` (now supports `targets[]`).

## Configuration

- `config/tool_paths.yaml` – configure absolute paths for ZAP, Nikto, etc.
- `config/config.yaml` (optional overrides):
  - `modules.module1.discovery.depth` / `max_endpoints`
  - `modules.module1.discovery.smart_wordlist` (true/false)
  - `modules.module1.fuzz.max_payloads`
  - `modules.module1.dos.enabled`, `requests`, `concurrency`

## Testing

- `pytest module1_input_validation/tests/test_module1_components.py`
- Tests focus on discovery, header analysis, target loading, and SQLi detection helpers. Extend with additional fixtures as needed for integration scenarios.

## Troubleshooting

- **Missing headers all false positives**: confirm target responds to HTTPS and no WAF rewriting.
- **Crawler too slow**: reduce `--depth` or `--max-endpoints`; enable caching via config `advanced.cache_enabled`.
- **Tool not found**: check `config/tool_paths.yaml` entries and file permissions.

## Notes & Safety

- **HTTP smuggling** and **DoS** testers are intentionally conservative—tunable via config.
- File uploads use harmless sample payloads but still respect server responses; no shell writes/execution.
- XML/XXE probes use non-destructive `file:///etc/passwd` references purely to gauge parser behavior.
- Always obtain permission before scanning; respect the legal constraints of your target environment.
