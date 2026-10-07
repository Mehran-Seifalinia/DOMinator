# DOMinator - DOM XSS Scanner

DOMinator is a powerful tool for detecting and analyzing DOM XSS vulnerabilities in web applications. It combines static and dynamic analysis techniques to provide comprehensive security testing.

---

## Features

- Static analysis of HTML and JavaScript code
- Dynamic analysis using headless browser automation
- Event handler extraction and analysis
- External script analysis
- Risk level assessment and prioritization
- Multiple output formats (JSON, CSV)
- Configurable scanning options
- Concurrent processing support
- Detailed logging and reporting

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Mehran-Seifalinia/DOMinator.git
cd DOMinator
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Playwright browser setup

On the first run, DOMinator will attempt to automatically download and install Chromium.

If the automatic installation fails (for example due to network restrictions or censorship), you will see a warning message with manual installation instructions.

In that case, install Chromium manually:

```bash
playwright install chromium
```

---

## Testing

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests -q
```

The suite covers the pure modules (HTML parsing, pattern risk mapping, payload
management, result merging, event handler extraction) and the command line,
including a check that `--dry-run` returns without opening a connection.

---

## Lab suite

`labs/` holds one fixture per detection scenario plus `labs/manifest.json`, the
ground truth of every fixture. `tools/lab_runner.py` serves them, scans them and
scores the outcome:

```bash
python tools/lab_runner.py                     # scan every lab and print a scored row
python tools/lab_runner.py --reuse             # re-score the saved scans, no browser
python tools/lab_runner.py --only 15-comment-only
```

A row is `PASS` only when every expected pattern appears (no false negative) and
no forbidden pattern appears (no false positive). The raw JSON and the log of
every scan stay in `.tmp/lab-results/`.

## Command line matrix

`tools/cli_matrix.py` exercises every command line parameter:

```bash
python tools/cli_matrix.py --tier plan       # parse and plan cases, no browser
python tools/cli_matrix.py --tier behavior   # real scans against the lab target
python tools/cli_matrix.py --dry-run         # list the cases only
```

Both runners need full access on Windows: Playwright opens named pipes that the
DSH sandbox blocks.

---

## Dry run

`--dry-run` prints the plan of a scan without sending any request and without
launching a browser:

```bash
python dominator.py -u https://example.com --dry-run
```

---

## Usage

### Basic usage

```bash
python dominator.py -u https://example.com
```

### Advanced usage

```bash
python dominator.py -u https://example.com -l 3 -t 4 -o results.json -r json -v
```

---

## Command Line Arguments

| Argument | Description |
|---|---|
| `-u, --url` | Target URL(s) to scan |
| `-t, --threads` | Number of threads for parallel processing |
| `-f, --force` | Force continue: exit 0 even when no target was reachable |
| `-o, --output` | Output file for saving results |
| `-l, --level` | Analysis level: 1 static only, 2 add dynamic, 3 add handlers and external scripts, 4 add a second payload attempt |
| `-to, --timeout` | Set timeout for HTTP requests |
| `-L, --list-url` | Path to a file containing a list of URLs |
| `-r, --report-format` | Report format (`json`, `html`, `csv`) |
| `-p, --proxy` | Set proxy for HTTP requests |
| `-v, --verbose` | Enable verbose output |
| `-q, --quiet` | Suppress all info logs, show only final report |
| `-b, --blacklist` | Comma-separated URLs, hosts, directories or `*` patterns to exclude |
| `--no-external` | Skip external JavaScript files |
| `--visible` | Show the browser window (disable headless mode) |
| `--user-agent` | Set custom User-Agent |
| `--cookie` | Send custom cookies |
| `--max-depth` | Set maximum crawling depth; crawling always stays on the host of the starting URL |
| `--auto-update` | Refresh the payload list from `--payload-source` or `DOMINATOR_PAYLOAD_SOURCE` before scanning |
| `--payload-source` | Payload document for `--auto-update`: an http(s) URL or a local JSON file |
| `--dry-run` | Print the scan plan and exit without sending requests or launching a browser |

---

## Project Structure

```text
DOMinator/
├── extractors/
│   ├── event_handler_extractor.py
│   ├── external_fetcher.py
│   └── html_parser.py
├── scanners/
│   ├── dynamic_analyzer.py
│   ├── static_analyzer.py
│   └── priority_manager.py
├── utils/
│   ├── analysis_result.py
│   ├── browser_setup.py
│   ├── dom_instrument.js
│   ├── logger.py
│   ├── patterns.py
│   └── payloads.py
├── tests/
│   ├── test_analysis_result.py
│   ├── test_cli.py
│   ├── test_cli_matrix.py
│   ├── test_console.py
│   ├── test_console_report.py
│   ├── test_event_handler_extractor.py
│   ├── test_html_parser.py
│   ├── test_lab_runner.py
│   ├── test_lab_server.py
│   ├── test_patterns.py
│   └── test_payloads.py
├── labs/
│   ├── manifest.json
│   ├── dom-xss-lab/
│   └── 01-hash-innerhtml/ ... 21-slow-response/
├── tools/
│   ├── cli_matrix.py
│   ├── lab_runner.py
│   └── lab_server.py
├── conftest.py
├── dominator.py
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

---

## Analysis Levels

| Level | What it does |
|---|---|
| 1 | Static analysis only: fetches the page and matches the sink and source patterns, no browser |
| 2 | Adds the dynamic analysis: installs the browser instrumentation and confirms a finding with a real payload |
| 3 | Adds inline event handler extraction and the analysis of external scripts (the default) |
| 4 | Adds a second payload variant when the first one does not fire |

Level 1 is the fast path: it starts no browser at all, so it also works where
Playwright cannot run.

---

## Output Format

The tool generates detailed reports including:

- Static analysis results
- Dynamic analysis findings
- Event handler vulnerabilities
- External script risks
- Risk levels and priorities
- Context and location information

---

## Troubleshooting

### Browser installation fails

If you see an error about Chromium not being installed and the automatic installation fails, run:

```bash
playwright install chromium
```

### Scan results not saved

Use the `-o` flag to specify an output file:

```bash
python dominator.py -u https://example.com -o results.csv
```

### Proxy or network issues

Make sure your environment can reach the target application.  
The tool respects the `-p` option for proxy configuration.

### pip install fails with Permission denied

Inside a restricted Windows sandbox the managed temp directory is not writable
and pip fails with `Permission denied` on a `pip-unpack-*` path. Point `TEMP`
and `TMP` at a directory inside the project before installing:

```powershell
$env:TEMP = "$PWD\.tmp"
$env:TMP  = "$PWD\.tmp"
python -m pip install -r requirements.txt
```

---

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

---

## License

This project is licensed under the MIT License.  
See the `LICENSE` file for details.

---

## Acknowledgments

- BeautifulSoup4 for HTML parsing
- Playwright for browser automation
- aiohttp for async HTTP requests
