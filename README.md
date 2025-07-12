# InsightLog

InsightLog is a Python script for extracting and analyzing data from server log files (Nginx, Apache2, and Auth logs). It provides tools to filter, parse, and analyze common server log formats.

## Features

- Filter log files by date, IP, log level, or custom patterns
- Extract web requests and authentication attempts from logs
- Analyze logs from Nginx, Apache2, and system Auth logs
- Export filtered results to JSON or CSV
- Display progress bar for large log files
- Command-line interface with flexible output and filtering options
- Improved error and warning logging
- Robust handling of malformed or partial log entries

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/CyberstepsDE/insightlog.git
   cd insightlog
   ```
2. (Optional) Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install requirements:
   ```bash
   pip3 install -r requirements.txt
   ```

## Usage Example (as a Python module)

```python
from insightlog.lib import InsightLogAnalyzer

analyzer = InsightLogAnalyzer('nginx', filepath='logs-samples/nginx1.sample')
analyzer.add_filter('192.10.1.1')
requests = analyzer.get_requests()
print(requests)
```

## Command Line Usage

You can also run the analyzer as a script from the project root:

```bash
python3 main.py --service nginx --logfile logs-samples/nginx1.sample --filter 192.10.1.1
```

More examples:

- Analyze Apache2 logs for a specific IP:
  ```bash
  python3 main.py --service apache2 --logfile logs-samples/apache1.sample --filter 127.0.1.1
  ```

- Analyze Auth logs for a specific string:
  ```bash
  python3 main.py --service auth --logfile logs-samples/auth.sample --filter root
  ```

- Analyze all Nginx log entries (no filter):
  ```bash
  python3 main.py --service nginx --logfile logs-samples/nginx1.sample
  ```

## Known Bugs

See [KNOWN_BUGS.md](KNOWN_BUGS.md) for a list of current bugs and how to replicate them.

## Planned Features

See [ROADMAP.md](ROADMAP.md) for planned features and improvements.

## Running Tests

We use `pytest` for testing. To run the tests:
```bash
pip3 install pytest
python3 -m pytest
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.