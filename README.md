# DOMinator - DOM XSS Scanner

DOMinator is a powerful tool for detecting and analyzing DOM XSS vulnerabilities in web applications. It combines static and dynamic analysis techniques to provide comprehensive security testing.

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

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/DOMinator.git
cd DOMinator
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install Playwright browsers:
```bash
playwright install
```

## Usage

Basic usage:
```bash
python dominator.py -u https://example.com
```

Advanced options:
```bash
python dominator.py -u https://example.com -l 3 -t 4 -o results.json -r json --headless
```

### Command Line Arguments

- `-u, --url`: Target URL(s) to scan
- `-t, --threads`: Number of threads for parallel processing
- `-f, --force`: Force continue even if site is not reachable
- `-o, --output`: Output file for saving results
- `-l, --level`: Set analysis level (1-4)
- `-to, --timeout`: Set timeout for HTTP requests
- `-L, --list-url`: Path to file containing list of URLs
- `-r, --report-format`: Choose report format (json, html, csv)
- `-p, --proxy`: Set proxy for HTTP requests
- `-v, --verbose`: Enable verbose output
- `-b, --blacklist`: Comma-separated list of URLs to exclude
- `--no-external`: Skip external JS files
- `--headless`: Enable headless browser mode
- `--user-agent`: Set custom User-Agent
- `--cookie`: Send custom cookies
- `--max-depth`: Set maximum crawling depth
- `--auto-update`: Auto-update payloads

## Project Structure

```
DOMinator/
├── extractors/
│   ├── event_handler_extractor.py
│   ├── external_fetcher.py
│   ├── html_parser.py
│   └── test_html_parser.py
├── scanners/
│   ├── dynamic_analyzer.py
│   ├── static_analyzer.py
│   └── priority_manager.py
├── utils/
│   ├── analysis_result.py
│   ├── logger.py
│   ├── patterns.py
│   └── payloads.py
├── dominator.py
├── requirements.txt
└── README.md
```

## Analysis Levels

1. Basic: Quick scan for obvious vulnerabilities
2. Standard: Comprehensive analysis with moderate depth
3. Deep: In-depth analysis with extended coverage
4. Expert: Maximum depth with advanced techniques

## Output Format

The tool generates detailed reports including:
- Static analysis results
- Dynamic analysis findings
- Event handler vulnerabilities
- External script risks
- Risk levels and priorities
- Context and location information

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- BeautifulSoup4 for HTML parsing
- Playwright for browser automation
- aiohttp for async HTTP requests
