#!/usr/bin/env python3
"""
JS Scanner - Crawl website and analyze all JavaScript files
Features: Extract JS files from website, analyze for secrets and endpoints
"""

import os
import re
import sys
import json
import argparse
import urllib.request
import urllib.parse
import html.parser
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set


# ========== Regex Patterns ==========

ENDPOINT_PATTERN = re.compile(r'''['"`](/[a-zA-Z0-9_/\-.*{}]+)['"`]''')
URL_PATTERN = re.compile(r'''https?://([a-zA-Z0-9\-\.]+)(/[a-zA-Z0-9_/\-.*?]*)?''')

# Secrets (same as js_analyzer)
AWS_ACCESS_KEY = re.compile(r'AKIA[0-9A-Z]{16}')
AWS_SECRET_KEY = re.compile(r'(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*["\']([a-zA-Z0-9/+=]{40})["\']')
ALIYUN_ACCESS_KEY = re.compile(r'(?i)(aliyun[_-]?access[_-]?key[_-]?id|access[_-]?key[_-]?id)\s*[=:]\s*["\']([a-zA-Z0-9]{16,})["\']')
ALIYUN_SECRET_KEY = re.compile(r'(?i)(aliyun[_-]?access[_-]?key[_-]?secret|secret[_-]?key)\s*[=:]\s*["\']([a-zA-Z0-9/+=]{20,})["\']')
TENCENT_SECRET_ID = re.compile(r'(?i)(tencent[_-]?secret[_-]?id|secret[_-]?id)\s*[=:]\s*["\']([a-zA-Z0-9]{20,})["\']')
TENCENT_SECRET_KEY = re.compile(r'(?i)(tencent[_-]?secret[_-]?key|secret[_-]?key)\s*[=:]\s*["\']([a-zA-Z0-9]{20,})["\']')
WECHAT_APPID = re.compile(r'(?i)(wechat_appid|wx_appid|appid)\s*[=:]\s*["\'](wx[0-9a-zA-Z]{16})["\']')
WECHAT_APPSECRET = re.compile(r'(?i)(wechat_appsecret|wx_appsecret|appsecret)\s*[=:]\s*["\']([a-zA-Z0-9]{32})["\']')
WECOM_CORP_ID = re.compile(r'(?i)(wecom_corp_id|corpid)\s*[=:]\s*["\'](\w+)["\']')
WECOM_CORP_SECRET = re.compile(r'(?i)(wecom_corp_secret|corpsecret)\s*[=:]\s*["\']([a-zA-Z0-9]{20,})["\']')
WECOM_AGENT_ID = re.compile(r'(?i)(wecom_agent_id|agentid)\s*[=:]\s*["\'](\d+)["\']')
GITHUB_TOKEN = re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}')
SLACK_TOKEN = re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*')
SLACK_WEBHOOK = re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+')
DINGTALK_WEBHOOK = re.compile(r'https://oapi\.dingtalk\.com/robot/send\?access_token=[a-zA-Z0-9]+')
STRIPE_KEY = re.compile(r'sk_live_[0-9a-zA-Z]{24}')
GOOGLE_API_KEY = re.compile(r'AIza[0-9A-Za-z_-]{35}')
JWT_PATTERN = re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*')
MONGO_URI = re.compile(r'mongodb(\+srv)?://[^\s\'"<>]+')
REDIS_URI = re.compile(r'redis://:[^\s\'"<>]+@')
PRIVATE_KEY_PATTERN = re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----')
API_KEY_PATTERN = re.compile(r'(?i)(api[_-]?key|apikey|token|secret)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']')

# Vulnerabilities
XSS_SINKS = ['innerHTML', 'outerHTML', 'document.write', 'eval(', 'setTimeout(', 'setInterval(']
SQL_KEYWORDS = ['sql', 'query', 'select', 'insert', 'update', 'delete', 'where', 'from']
CMD_EXEC = ['exec(', 'execSync(', 'spawn(', 'system(', 'shell_exec', 'child_process']


class JSLinkParser(html.parser.HTMLParser):
    """Extract JS file URLs from HTML"""
    
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.js_files = set()
    
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'script':
            src = attrs_dict.get('src', '')
            if src:
                self.js_files.add(urljoin(self.base_url, src))
        elif tag == 'link':
            href = attrs_dict.get('href', '')
            if href and '.js' in href:
                self.js_files.add(urljoin(self.base_url, href))


class JSAnalyzer:
    """Analyze JS file for secrets"""
    
    def __init__(self):
        self.endpoints = set()
        self.domains = set()
        self.secrets = []
        self.vulnerabilities = []
        
    def analyze(self, content: str, source_url: str = "") -> dict:
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            if line.strip().startswith('//'):
                continue
            
            for match in ENDPOINT_PATTERN.finditer(line):
                endpoint = match.group(1)
                if endpoint and len(endpoint) > 1:
                    self.endpoints.add(endpoint)
            
            for match in URL_PATTERN.finditer(line):
                domain = match.group(1)
                if domain:
                    self.domains.add(domain)
            
            # AWS
            for match in AWS_ACCESS_KEY.finditer(line):
                self.secrets.append({'type': 'AWS_ACCESS_KEY', 'value': match.group(1)[:10]+'...', 'line': i, 'source': source_url})
            for match in AWS_SECRET_KEY.finditer(line):
                self.secrets.append({'type': 'AWS_SECRET_KEY', 'value': match.group(2)[:10]+'...', 'line': i, 'source': source_url})
            
            # Aliyun
            for match in ALIYUN_ACCESS_KEY.finditer(line):
                self.secrets.append({'type': 'ALIYUN_ACCESS_KEY', 'value': match.group(2)[:10]+'...', 'line': i, 'source': source_url})
            for match in ALIYUN_SECRET_KEY.finditer(line):
                self.secrets.append({'type': 'ALIYUN_SECRET_KEY', 'value': match.group(2)[:10]+'...', 'line': i, 'source': source_url})
            
            # Tencent
            for match in TENCENT_SECRET_ID.finditer(line):
                self.secrets.append({'type': 'TENCENT_SECRET_ID', 'value': match.group(2)[:10]+'...', 'line': i, 'source': source_url})
            for match in TENCENT_SECRET_KEY.finditer(line):
                self.secrets.append({'type': 'TENCENT_SECRET_KEY', 'value': match.group(2)[:10]+'...', 'line': i, 'source': source_url})
            
            # WeChat
            for match in WECHAT_APPID.finditer(line):
                self.secrets.append({'type': 'WECHAT_APPID', 'value': match.group(2), 'line': i, 'source': source_url})
            for match in WECHAT_APPSECRET.finditer(line):
                self.secrets.append({'type': 'WECHAT_APPSECRET', 'value': match.group(2)[:10]+'...', 'line': i, 'source': source_url})
            
            # WeCom
            for match in WECOM_CORP_ID.finditer(line):
                self.secrets.append({'type': 'WECOM_CORP_ID', 'value': match.group(2), 'line': i, 'source': source_url})
            for match in WECOM_CORP_SECRET.finditer(line):
                self.secrets.append({'type': 'WECOM_CORP_SECRET', 'value': match.group(2)[:10]+'...', 'line': i, 'source': source_url})
            for match in WECOM_AGENT_ID.finditer(line):
                self.secrets.append({'type': 'WECOM_AGENT_ID', 'value': match.group(2), 'line': i, 'source': source_url})
            
            # GitHub
            for match in GITHUB_TOKEN.finditer(line):
                self.secrets.append({'type': 'GITHUB_TOKEN', 'value': match.group(0)[:15]+'...', 'line': i, 'source': source_url})
            
            # Slack
            for match in SLACK_TOKEN.finditer(line):
                self.secrets.append({'type': 'SLACK_TOKEN', 'value': match.group(0)[:15]+'...', 'line': i, 'source': source_url})
            for match in SLACK_WEBHOOK.finditer(line):
                self.secrets.append({'type': 'SLACK_WEBHOOK', 'value': match.group(0)[:50]+'...', 'line': i, 'source': source_url})
            
            # DingTalk
            for match in DINGTALK_WEBHOOK.finditer(line):
                self.secrets.append({'type': 'DINGTALK_WEBHOOK', 'value': match.group(0)[:50]+'...', 'line': i, 'source': source_url})
            
            # Stripe
            for match in STRIPE_KEY.finditer(line):
                self.secrets.append({'type': 'STRIPE_KEY', 'value': match.group(0)[:15]+'...', 'line': i, 'source': source_url})
            
            # Google
            for match in GOOGLE_API_KEY.finditer(line):
                self.secrets.append({'type': 'GOOGLE_API_KEY', 'value': match.group(0)[:20]+'...', 'line': i, 'source': source_url})
            
            # JWT
            for match in JWT_PATTERN.finditer(line):
                self.secrets.append({'type': 'JWT_TOKEN', 'value': match.group(0)[:30]+'...', 'line': i, 'source': source_url})
            
            # MongoDB/Redis
            for match in MONGO_URI.finditer(line):
                self.secrets.append({'type': 'MONGO_URI', 'value': match.group(0)[:40]+'...', 'line': i, 'source': source_url})
            for match in REDIS_URI.finditer(line):
                self.secrets.append({'type': 'REDIS_URI', 'value': match.group(0)[:40]+'...', 'line': i, 'source': source_url})
            
            # Private Key
            if PRIVATE_KEY_PATTERN.search(line):
                self.secrets.append({'type': 'PRIVATE_KEY', 'line': i, 'source': source_url})
            
            # Generic API Key
            for match in API_KEY_PATTERN.finditer(line):
                if len(match.group(2)) > 15:
                    self.secrets.append({'type': 'API_KEY', 'key': match.group(1), 'value': match.group(2)[:12]+'...', 'line': i, 'source': source_url})
            
            # Vulnerabilities
            for sink in XSS_SINKS:
                if sink in line:
                    self.vulnerabilities.append({'type': 'XSS', 'sink': sink, 'line': i, 'source': source_url})
            
            for cmd in CMD_EXEC:
                if cmd in line:
                    self.vulnerabilities.append({'type': 'CMD_INJECTION', 'sink': cmd, 'line': i, 'source': source_url})
        
        return self.get_results()
    
    def get_results(self):
        return {
            'endpoints': sorted(list(self.endpoints)),
            'domains': sorted(list(self.domains)),
            'secrets': self.secrets,
            'vulnerabilities': self.vulnerabilities
        }


def fetch_url(url: str, timeout: int = 30) -> str:
    """Fetch URL content"""
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode('utf-8', errors='ignore')


def extract_js_links(html_content: str, base_url: str) -> List[str]:
    """Extract JS file links from HTML"""
    parser = JSLinkParser(base_url)
    parser.feed(html_content)
    return list(parser.js_files)


def scan_site(target_url: str, verbose: bool = False) -> dict:
    """Scan website for JS files and analyze"""
    if not target_url.startswith('http'):
        target_url = 'http://' + target_url
    
    print(f"[*] Fetching: {target_url}")
    
    try:
        html = fetch_url(target_url)
    except Exception as e:
        return {'error': f"Failed to fetch: {e}"}
    
    js_files = extract_js_links(html, target_url)
    print(f"[*] Found {len(js_files)} JS files")
    
    all_results = {
        'target': target_url,
        'js_files': [],
        'endpoints': set(),
        'domains': set(),
        'secrets': [],
        'vulnerabilities': []
    }
    
    analyzer = JSAnalyzer()
    
    # Analyze inline JS
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
    for i, script in enumerate(inline_scripts):
        if script.strip():
            result = analyzer.analyze(script, f"{target_url}#inline-{i}")
            all_results['endpoints'].update(result['endpoints'])
            all_results['domains'].update(result['domains'])
            all_results['secrets'].extend(result['secrets'])
            all_results['vulnerabilities'].extend(result['vulnerabilities'])
    
    # Fetch external JS files
    for js_url in js_files[:50]:  # Limit to 50 files
        try:
            if verbose:
                print(f"    -> {js_url}")
            
            js_content = fetch_url(js_url)
            result = analyzer.analyze(js_content, js_url)
            
            all_results['js_files'].append(js_url)
            all_results['endpoints'].update(result['endpoints'])
            all_results['domains'].update(result['domains'])
            all_results['secrets'].extend(result['secrets'])
            all_results['vulnerabilities'].extend(result['vulnerabilities'])
            
        except Exception as e:
            if verbose:
                print(f"    ! Error: {js_url} - {e}")
    
    all_results['endpoints'] = sorted(list(all_results['endpoints']))
    all_results['domains'] = sorted(list(all_results['domains']))
    all_results['js_files'] = all_results['js_files'][:50]
    
    return all_results


def cmd_scan(args):
    """Scan website"""
    result = scan_site(args.url, verbose=args.verbose)
    
    if 'error' in result:
        print(f"Error: {result['error']}")
        return
    
    print(f"\n=== Scan Results: {args.url} ===\n")
    print(f"JS Files: {len(result['js_files'])}")
    print(f"Endpoints: {len(result['endpoints'])}")
    print(f"Domains: {len(result['domains'])}")
    print(f"Secrets: {len(result['secrets'])}")
    print(f"Vulnerabilities: {len(result['vulnerabilities'])}")
    
    if result['secrets']:
        print(f"\n[!] Secrets Found:")
        secret_types = {}
        for s in result['secrets']:
            t = s['type']
            secret_types[t] = secret_types.get(t, 0) + 1
        
        for t, count in sorted(secret_types.items(), key=lambda x: x[1], reverse=True):
            print(f"    {t}: {count}")
    
    if result['vulnerabilities']:
        print(f"\n[!] Vulnerabilities:")
        vuln_types = {}
        for v in result['vulnerabilities']:
            t = v['type']
            vuln_types[t] = vuln_types.get(t, 0) + 1
        
        for t, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            print(f"    {t}: {count}")
    
    if args.json:
        print("\n" + json.dumps(result, indent=2))


def cmd_crawl(args):
    """Crawl website and list all JS files"""
    if not args.url.startswith('http'):
        args.url = 'http://' + args.url
    
    print(f"[*] Crawling: {args.url}")
    
    try:
        html = fetch_url(args.url)
        js_files = extract_js_links(html, args.url)
        
        print(f"\n[*] Found {len(js_files)} JS files:\n")
        for i, js in enumerate(js_files, 1):
            print(f"  {i}. {js}")
        
    except Exception as e:
        print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="JS Scanner - Crawl and analyze website JS files")
    subparsers = parser.add_subparsers(dest="cmd")
    
    # scan
    p = subparsers.add_parser("scan", help="Scan website for JS secrets")
    p.add_argument("url", help="Target URL")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")
    
    # crawl
    p = subparsers.add_parser("crawl", help="List all JS files from website")
    p.add_argument("url", help="Target URL")
    
    args = parser.parse_args()
    
    if not args.cmd:
        parser.print_help()
        return
    
    try:
        if args.cmd == "scan":
            cmd_scan(args)
        elif args.cmd == "crawl":
            cmd_crawl(args)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
