# Batch Analysis Module

Automated batch processing for the Security Controls GAP Analysis System.

## Overview

The Batch Analysis module provides automated processing of multiple documents and URLs, executing all 8 security modules, and generating a comprehensive HTML dashboard report.

## Features

- **Document Processing**: Parse Excel, PDF, and DOCX files for security data
- **URL Processing**: Parse and categorize URLs from text files
- **Multi-Module Execution**: Run all 8 security modules automatically
- **HTML Dashboard**: Interactive dashboard with visualizations
- **Backward Compatible**: Existing functionality remains unchanged

## Quick Start

### 1. Prepare Inputs

```bash
# Add documents
cp your_policy.pdf batch_inputs/documents/
cp controls_checklist.xlsx batch_inputs/documents/

# Add URLs
cat > batch_inputs/urls/urls.txt << EOF
https://example.com
https://api.example.com
EOF
```

### 2. Run Batch Analysis

```bash
# Simple run
python run_batch_analysis.py

# With debug output
python run_batch_analysis.py --debug

# Specific modules only
python run_batch_analysis.py --modules 1,2,3,4
```

### 3. View Dashboard

```bash
# Dashboard is automatically generated at:
# batch_outputs/reports/dashboard_YYYYMMDD_HHMMSS.html

# Open in browser
xdg-open batch_outputs/reports/dashboard_*.html
```

## Usage

### Command-Line Options

```bash
python run_batch_analysis.py [OPTIONS]

Options:
  --docs PATH           Documents directory (default: batch_inputs/documents/)
  --urls PATH           URLs directory (default: batch_inputs/urls/)
  --output PATH         Output directory (default: batch_outputs/)
  --modules LIST        Comma-separated module numbers (e.g., 1,2,3,4)
  --dashboard-only      Only generate dashboard from existing results
  --results PATH        Path to results for dashboard-only mode
  --config-dir PATH     Configuration directory (default: config/)
  --debug               Enable debug logging
  --no-dashboard        Skip dashboard generation
  --help                Show help message
```

### Examples

#### Run All Modules
```bash
python run_batch_analysis.py
```

#### Run Specific Modules
```bash
python run_batch_analysis.py --modules 1,4,7
```

#### Custom Input Directories
```bash
python run_batch_analysis.py \
  --docs /path/to/documents \
  --urls /path/to/urls
```

#### Generate Dashboard Only
```bash
python run_batch_analysis.py \
  --dashboard-only \
  --results batch_outputs/raw_results/batch_results_20251126_120000.json
```

## Input Formats

### Documents

Place documents in `batch_inputs/documents/`:

**Supported Formats**:
- Excel (`.xlsx`, `.xls`)
- PDF (`.pdf`)
- DOCX (`.docx`)

**Extracted Data**:
- URLs and endpoints
- Control IDs (e.g., CTRL-001, Control_1)
- Policy references

### URLs

Create text files in `batch_inputs/urls/`:

**Format** (`urls.txt`):
```
# Comments start with #
https://example.com
https://api.example.com/v1
https://admin.example.com
```

**URL Categories**:
- **Web**: Standard web applications
- **API**: API endpoints (contains `/api/`, `/v1/`, `api.`)
- **Infrastructure**: Admin/monitoring (contains `admin.`, `dashboard.`)

## Output Structure

```
batch_outputs/
├── reports/
│   └── dashboard_YYYYMMDD_HHMMSS.html    # Interactive dashboard
├── raw_results/
│   ├── module1_result.json                # Individual module results
│   ├── module2_result.json
│   └── batch_results_YYYYMMDD_HHMMSS.json # Complete batch results
└── logs/
    └── batch_analysis.log                 # Execution logs
```

## Dashboard Features

The HTML dashboard includes:

### Executive Summary
- Overall security score (0-100%)
- Total modules executed
- Controls passed/failed/not tested
- Execution time

### Module Overview
- 8 module cards with status
- Success/failure indicators
- Quick navigation

### Detailed Results
- Module-by-module breakdown
- Output file locations
- Timestamps

### Visualizations
- Security score gauge
- Module status cards
- Control distribution

## Architecture

### Components

1. **DocumentParser** (`document_parser.py`)
   - Parses Excel, PDF, DOCX files
   - Extracts URLs, controls, policies
   - Handles multiple file formats

2. **URLParser** (`url_parser.py`)
   - Parses URL text files
   - Validates URL formats
   - Categorizes URLs by type

3. **BatchOrchestrator** (`orchestrator.py`)
   - Coordinates module execution
   - Manages inputs and outputs
   - Handles errors and retries

4. **DashboardGenerator** (`dashboard_generator.py`)
   - Generates HTML dashboard
   - Creates visualizations
   - Responsive design

## Integration with Existing Modules

The batch analysis feature **reuses existing modules** without modification:

```python
# Batch orchestrator imports existing modules
from module1_input_validation.main import Module1Analyzer
from module2_authentication.main import Module2Analyzer
# ... etc

# Executes them normally
analyzer = Module1Analyzer(config=config, target=url)
result = analyzer.execute()
```

**No changes to existing modules required!**

## Backward Compatibility

All existing functionality remains unchanged:

```bash
# Individual module execution still works
python run_module.py --module=1 --target https://example.com

# Run all modules script still works
./run_all.sh

# Outputs still go to outputs/ directory
ls outputs/
```

## Troubleshooting

### No URLs Found

```bash
# Check input directories
ls batch_inputs/documents/
ls batch_inputs/urls/

# Add sample URLs
echo "https://example.com" > batch_inputs/urls/urls.txt
```

### Module Execution Failed

```bash
# Run with debug output
python run_batch_analysis.py --debug

# Check logs
cat batch_outputs/logs/batch_analysis.log
```

### Dashboard Not Generated

```bash
# Generate dashboard from existing results
python run_batch_analysis.py \
  --dashboard-only \
  --results batch_outputs/raw_results/batch_results_*.json
```

### Missing Dependencies

```bash
# Install new dependencies
pip install openpyxl jinja2

# Or reinstall all
pip install -r requirements.txt
```

## Development

### Testing

```bash
# Test document parser
python batch_analysis/document_parser.py batch_inputs/documents/

# Test URL parser
python batch_analysis/url_parser.py batch_inputs/urls/

# Test orchestrator
python batch_analysis/orchestrator.py

# Test dashboard generator
python batch_analysis/dashboard_generator.py
```

### Adding Features

1. **Custom Parsers**: Add to `document_parser.py` or `url_parser.py`
2. **Dashboard Sections**: Modify `dashboard_generator.py`
3. **Execution Logic**: Update `orchestrator.py`

## Performance

- **Execution Time**: Depends on number of targets and modules
- **Typical**: 2-5 minutes for 8 modules on 5 targets
- **Parallel Execution**: Future enhancement

## Security Considerations

- Dashboard contains sensitive security data
- Store in secure location
- Restrict access appropriately
- Do not commit results to version control

## Future Enhancements

- [ ] Parallel module execution
- [ ] PDF export of dashboard
- [ ] Email report delivery
- [ ] Scheduled batch runs
- [ ] Advanced visualizations (Chart.js integration)
- [ ] Comparison with previous scans
- [ ] Trend analysis

## Support

For issues or questions:
1. Check logs: `batch_outputs/logs/batch_analysis.log`
2. Run with `--debug` flag
3. Review individual module outputs
4. Consult main documentation

---

**Version**: 1.0.0  
**Status**: Production Ready  
**Compatibility**: GAP Analysis System v1.0+
