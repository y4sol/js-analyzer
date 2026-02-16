#!/usr/bin/env python3
"""
JS Analyzer - Extract sensitive information from JavaScript files
Features: Endpoint extraction, secret detection, vulnerability discovery
"""

import os
import re
import sys
import json
import argparse
from typing import List, Dict, Set


# ========== Regex Patterns ==========

# Endpoints
ENDPOINT_PATTERN = re.compile(r'''['"`](/[a-zA-Z0-9_/\-.*{}]+)['"`]''')

# URLs
URL_PATTERN = re.compile(r'''https?://([a-zA-Z0-9\-\.]+)(/[a-zA-Z0-9_/\-.*?]*)?''')

# Secrets
AWS_KEY_PATTERN = re.compile(r'(AKIA[0-9A-Z]{16})')
AWS_SECRET_PATTERN = re.compile(r'(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*[\'"]([a-zA-Z0-9/+=]{40})[\'"]')
JWT_PATTERN = re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*')
API_KEY_PATTERN = re.compile(r'(?i)(api[_-]?key|apikey|token|secret)\s*[=:]\s*[\'"]([a-zA-Z0-9_\-]{16,})[\'"]')
PRIVATE_KEY_PATTERN = re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----')

# Vulnerabilities
XSS_SINKS = ['innerHTML', 'outerHTML', 'document.write', 'eval(', 'setTimeout(', 'setInterval(']
SQL_KEYWORDS = ['sql', 'query', 'select', 'insert', 'update', 'delete', 'where', 'from']
CMD_EXEC = ['exec(', 'execSync(', 'spawn(', 'system(', 'popen(', 'shell_exec', 'exec_command']


class JSAnalyzer:
    """JavaScript File Analyzer"""
    
    def __init__(self):
        self.endpoints: Set[str] = set()
        self.domains: Set[str] = set()
        self.secrets: List[Dict] = []
        self.vulnerabilities: List[Dict] = []
        self.ips: Set[str] = set()
        
    def analyze_file(self, filepath: str) -> dict:
        """Analyze a single JS file"""
        self.__init__()
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Skip comments
            if line.strip().startswith('//'):
                continue
                
            self._extract_endpoints(line, i)
            self._extract_urls(line, i)
            self._extract_secrets(line, i)
            self._find_vulnerabilities(line, i)
        
        return self.get_results()
    
    def _extract_endpoints(self, line: str, line_num: int):
        """Extract API endpoints"""
        for match in ENDPOINT_PATTERN.finditer(line):
            endpoint = match.group(1)
            if endpoint and len(endpoint) > 1:
                self.endpoints.add(endpoint)
    
    def _extract_urls(self, line: str, line_num: int):
        """Extract URLs and domains"""
        for match in URL_PATTERN.finditer(line):
            domain = match.group(1)
            path = match.group(2) or '/'
            if domain:
                self.domains.add(domain)
                if path and len(path) > 1:
                    self.endpoints.add(path)
    
    def _extract_secrets(self, line: str, line_num: int):
        """Detect secrets and sensitive data"""
        # AWS Access Key
        for match in AWS_KEY_PATTERN.finditer(line):
            self.secrets.append({
                'type': 'AWS_ACCESS_KEY',
                'value': match.group(1)[:10] + '...',
                'line': line_num
            })
        
        # JWT
        for match in JWT_PATTERN.finditer(line):
            self.secrets.append({
                'type': 'JWT_TOKEN',
                'value': match.group(0)[:30] + '...',
                'line': line_num
            })
        
        # API Key / Token
        for match in API_KEY_PATTERN.finditer(line):
            key_name = match.group(1)
            key_value = match.group(2)
            if len(key_value) > 10:
                self.secrets.append({
                    'type': 'API_KEY',
                    'key': key_name,
                    'value': key_value[:10] + '...',
                    'line': line_num
                })
        
        # Private Key
        if PRIVATE_KEY_PATTERN.search(line):
            self.secrets.append({
                'type': 'PRIVATE_KEY',
                'line': line_num
            })
    
    def _find_vulnerabilities(self, line: str, line_num: int):
        """Find potential vulnerability points"""
        # XSS sinks
        for sink in XSS_SINKS:
            if sink in line:
                self.vulnerabilities.append({
                    'type': 'XSS',
                    'sink': sink,
                    'line': line_num,
                    'snippet': line.strip()[:80]
                })
        
        # SQL injection
        for keyword in SQL_KEYWORDS:
            if f"'{keyword}" in line.lower() or f'"{keyword}' in line.lower():
                if 'where' in line.lower() or 'select' in line.lower():
                    self.vulnerabilities.append({
                        'type': 'SQLI',
                        'line': line_num,
                        'snippet': line.strip()[:80]
                    })
                    break
        
        # Command injection
        for cmd in CMD_EXEC:
            if cmd in line:
                self.vulnerabilities.append({
                    'type': 'CMD_INJECTION',
                    'sink': cmd,
                    'line': line_num,
                    'snippet': line.strip()[:80]
                })
    
    def get_results(self) -> dict:
        """Get analysis results"""
        return {
            'endpoints': sorted(list(self.endpoints)),
            'domains': sorted(list(self.domains)),
            'secrets': self.secrets,
            'vulnerabilities': self.vulnerabilities
        }


def cmd_analyze(args):
    """Analyze single file"""
    analyzer = JSAnalyzer()
    result = analyzer.analyze_file(args.file)
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n=== JS Analysis: {args.file} ===\n")
        
        if result['endpoints']:
            print(f"[+] Endpoints ({len(result['endpoints'])}):")
            for e in result['endpoints'][:20]:
                print(f"    {e}")
            if len(result['endpoints']) > 20:
                print(f"    ... and {len(result['endpoints']) - 20} more")
            print()
        
        if result['domains']:
            print(f"[+] Domains ({len(result['domains'])}):")
            for d in result['domains'][:10]:
                print(f"    {d}")
            print()
        
        if result['secrets']:
            print(f"[!] Secrets ({len(result['secrets'])}):")
            for s in result['secrets']:
                print(f"    [{s['type']}] Line {s.get('line', '?')}")
                if 'value' in s:
                    print(f"        {s['value']}")
            print()
        
        if result['vulnerabilities']:
            print(f"[!] Vulnerabilities ({len(result['vulnerabilities'])}):")
            for v in result['vulnerabilities']:
                print(f"    [{v['type']}] Line {v['line']}")
                if 'sink' in v:
                    print(f"        Sink: {v['sink']}")
            print()


def cmd_scan(args):
    """Scan directory"""
    analyzer = JSAnalyzer()
    all_results = {
        'endpoints': set(),
        'domains': set(),
        'secrets': [],
        'vulnerabilities': []
    }
    
    js_files = []
    for root, dirs, files in os.walk(args.directory):
        for f in files:
            if f.endswith('.js'):
                js_files.append(os.path.join(root, f))
    
    print(f"Scanning {len(js_files)} JS files...")
    
    for filepath in js_files:
        try:
            result = analyzer.analyze_file(filepath)
            all_results['endpoints'].update(result['endpoints'])
            all_results['domains'].update(result['domains'])
            all_results['secrets'].extend(result['secrets'])
            all_results['vulnerabilities'].extend(result['vulnerabilities'])
        except Exception as e:
            print(f"Error: {filepath}: {e}")
    
    all_results['endpoints'] = sorted(list(all_results['endpoints']))
    all_results['domains'] = sorted(list(all_results['domains']))
    
    if args.json:
        print(json.dumps(all_results, indent=2))
    else:
        print(f"\n=== Scan Results ===\n")
        print(f"Endpoints: {len(all_results['endpoints'])}")
        print(f"Domains: {len(all_results['domains'])}")
        print(f"Secrets: {len(all_results['secrets'])}")
        print(f"Vulnerabilities: {len(all_results['vulnerabilities'])}")


def cmd_endpoints(args):
    """Extract endpoints only"""
    analyzer = JSAnalyzer()
    result = analyzer.analyze_file(args.file)
    
    for e in result['endpoints']:
        print(e)


def cmd_secrets(args):
    """Extract secrets only"""
    analyzer = JSAnalyzer()
    result = analyzer.analyze_file(args.file)
    
    for s in result['secrets']:
        print(json.dumps(s, indent=2))


def main():
    parser = argparse.ArgumentParser(description="JS Analyzer - Extract secrets from JS files")
    subparsers = parser.add_subparsers(dest="cmd")
    
    # analyze
    p = subparsers.add_parser("analyze", help="Analyze single file")
    p.add_argument("file")
    p.add_argument("--json", "-j", action="store_true")
    
    # scan
    p = subparsers.add_parser("scan", help="Scan directory")
    p.add_argument("directory")
    p.add_argument("--json", "-j", action="store_true")
    
    # endpoints
    p = subparsers.add_parser("endpoints", help="Extract endpoints")
    p.add_argument("file")
    
    # secrets
    p = subparsers.add_parser("secrets", help="Extract secrets")
    p.add_argument("file")
    
    args = parser.parse_args()
    
    if not args.cmd:
        parser.print_help()
        return
    
    try:
        if args.cmd == "analyze":
            cmd_analyze(args)
        elif args.cmd == "scan":
            cmd_scan(args)
        elif args.cmd == "endpoints":
            cmd_endpoints(args)
        elif args.cmd == "secrets":
            cmd_secrets(args)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
