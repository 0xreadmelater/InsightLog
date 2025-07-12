import logging
logging.basicConfig(level=logging.INFO)
import argparse
import json
import csv
from insightlog.lib import InsightLogAnalyzer

def parse_args():
    parser = argparse.ArgumentParser(description="Analyze server log files (nginx, apache2, auth)")
    parser.add_argument('--service', required=True, choices=['nginx', 'apache2', 'auth'], help='Type of log to analyze')
    parser.add_argument('--logfile', required=True, help='Path to the log file')
    parser.add_argument('--filter', required=False, default=None, help='String to filter log lines')
    parser.add_argument('--output', choices=['json', 'csv'], help='Export format')
    return parser.parse_args()

def main():
    args = parse_args()

    analyzer = InsightLogAnalyzer(args.service, filepath=args.logfile)
    if args.filter:
        analyzer.add_filter(args.filter)
    requests = analyzer.get_requests()

    if args.output == 'json':
        with open('output.json', 'w', encoding='utf-8') as f:
            json.dump(requests, f, indent=2)
        logging.info("Exported results to output.json")
    elif args.output == 'csv':
        if requests:
            with open('output.csv', 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=requests[0].keys())
                writer.writeheader()
                writer.writerows(requests)
            logging.info("Exported results to output.csv")
        else:
            logging.warning("No data to write to CSV.")
    else:
        for req in requests:
            print(json.dumps(req, indent=2))

if __name__ == '__main__':
    main() 