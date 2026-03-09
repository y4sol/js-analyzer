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

# ========== Cloud Provider Secrets ==========

# AWS
AWS_ACCESS_KEY = re.compile(r'AKIA[0-9A-Z]{16}')
AWS_SECRET_KEY = re.compile(r'(?i)(aws_secret_access_key|aws_secret_key|aws_secret)\s*[=:]\s*[\'"]([a-zA-Z0-9/+=]{40})[\'"]')

# Aliyun (阿里云)
ALIYUN_ACCESS_KEY = re.compile(r'(?i)(aliyun[_-]?access[_-]?key[_-]?id|aliyun[_-]?accesskey|access[_-]?key[_-]?id)\s*[=:]\s*["\']([a-zA-Z0-9]{16,})["\']')
ALIYUN_SECRET_KEY = re.compile(r'(?i)(aliyun[_-]?access[_-]?key[_-]?secret|aliyun[_-]?secret|secret[_-]?key)\s*[=:]\s*["\']([a-zA-Z0-9/+=]{20,})["\']')

# Tencent Cloud (腾讯云)
TENCENT_SECRET_ID = re.compile(r'(?i)(tencent[_-]?secret[_-]?id|secret[_-]?id|qcloud[_-]?secret[_-]?id)\s*[=:]\s*["\']([a-zA-Z0-9]{20,})["\']')
TENCENT_SECRET_KEY = re.compile(r'(?i)(tencent[_-]?secret[_-]?key|secret[_-]?key|qcloud[_-]?secret[_-]?key)\s*[=:]\s*["\']([a-zA-Z0-9]{20,})["\']')

# Huawei Cloud (华为云)
HUAWEI_ACCESS_KEY = re.compile(r'(?i)(huawei_access_key|hw_access_key_id)\s*[=:]\s*[\'"]([a-zA-Z0-9]{20,})[\'"]')
HUAWEI_SECRET_KEY = re.compile(r'(?i)(huawei_secret_key|hw_secret_key)\s*[=:]\s*[\'"]([a-zA-Z0-9/+=]{40})[\'"]')

# ========== WeChat / WeCom ==========

# WeChat Mini Program (微信小程序)
WECHAT_APPID = re.compile(r'(?i)(wechat_appid|wx_appid|weixin_appid|appid)\s*[=:]\s*[\'"](wx[0-9a-zA-Z]{16})[\'"]')
WECHAT_APPSECRET = re.compile(r'(?i)(wechat_appsecret|wx_appsecret|weixin_secret|appsecret)\s*[=:]\s*[\'"]([a-zA-Z0-9]{32})[\'"]')

# WeCom (企业微信)
WECOM_CORP_ID = re.compile(r'(?i)(wecom_corp_id|corpid|wework_corp_id)\s*[=:]\s*["\'](\w+)["\']')
WECOM_CORP_SECRET = re.compile(r'(?i)(wecom_corp_secret|corpsecret|wework_secret)\s*[=:]\s*["\']([a-zA-Z0-9]{20,})["\']')
WECOM_AGENT_ID = re.compile(r'(?i)(wecom_agent_id|agentid|wework_agent_id)\s*[=:]\s*["\'](\d+)["\']')

# ========== Other Services ==========

# GitHub
GITHUB_TOKEN = re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}')
GITHUB_API_KEY = re.compile(r'(?i)(github_token|github_api_key)\s*[=:]\s*[\'"]([a-zA-Z0-9]{36,})[\'"]')

# Slack
SLACK_TOKEN = re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*')
SLACK_WEBHOOK = re.compile(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+')

# DingTalk (钉钉)
DINGTALK_APP_KEY = re.compile(r'(?i)(dingtalk_appkey|ding_app_key)\s*[=:]\s*[\'"]([a-zA-Z0-9]{20})[\'"]')
DINGTALK_SECRET = re.compile(r'(?i)(dingtalk_secret|ding_secret)\s*[=:]\s*[\'"]([a-zA-Z0-9]{40})[\'"]')
DINGTALK_WEBHOOK = re.compile(r'https://oapi\.dingtalk\.com/robot/send\?access_token=[a-zA-Z0-9]+')

# Stripe
STRIPE_KEY = re.compile(r'sk_live_[0-9a-zA-Z]{24}')

# SendGrid
SENDGRID_API_KEY = re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}')

# Twilio
TWILIO_ACCOUNT_SID = re.compile(r'AC[a-z0-9]{32}')
TWILIO_AUTH_TOKEN = re.compile(r'(?i)(twilio_auth_token|auth_token)\s*[=:]\s*[\'"]([a-zA-Z0-9]{32})[\'"]')

# MongoDB
MONGO_URI = re.compile(r'mongodb(\+srv)?://[^\s\'"<>]+')

# Redis
REDIS_URI = re.compile(r'redis://:[^\s\'"<>]+@')

# JWT
JWT_PATTERN = re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*')

# Generic API Key
API_KEY_PATTERN = re.compile(r'(?i)(api[_-]?key|apikey|token|secret|password|passwd)\s*[=:]\s*[\'"]([a-zA-Z0-9_\-]{16,})[\'"]')

# Private Key
PRIVATE_KEY_PATTERN = re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')

# Google API
GOOGLE_API_KEY = re.compile(r'AIza[0-9A-Za-z_-]{35}')

# Facebook
FACEBOOK_ACCESS_TOKEN = re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+')

# ========== Vulnerabilities ==========

XSS_SINKS = ['innerHTML', 'outerHTML', 'document.write', 'eval(', 'setTimeout(', 'setInterval(']
SQL_KEYWORDS = ['sql', 'query', 'select', 'insert', 'update', 'delete', 'where', 'from']
CMD_EXEC = ['exec(', 'execSync(', 'spawn(', 'system(', 'popen(', 'shell_exec', 'exec_command', 'child_process']


class JSAnalyzer:
    """JavaScript File Analyzer"""
    
    def __init__(self):
        self.endpoints: Set[str] = set()
        self.domains: Set[str] = set()
        self.secrets: List[Dict] = []
        self.vulnerabilities: List[Dict] = []
        
    def analyze_file(self, filepath: str) -> dict:
        """Analyze a single JS file"""
        self.__init__()
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            if line.strip().startswith('//'):
                continue
                
            self._extract_endpoints(line, i)
            self._extract_urls(line, i)
            self._extract_secrets(line, i)
            self._find_vulnerabilities(line, i)
        
        return self.get_results()
    
    def _extract_endpoints(self, line: str, line_num: int):
        for match in ENDPOINT_PATTERN.finditer(line):
            endpoint = match.group(1)
            if endpoint and len(endpoint) > 1:
                self.endpoints.add(endpoint)
    
    def _extract_urls(self, line: str, line_num: int):
        for match in URL_PATTERN.finditer(line):
            domain = match.group(1)
            path = match.group(2) or '/'
            if domain:
                self.domains.add(domain)
                if path and len(path) > 1:
                    self.endpoints.add(path)
    
    def _extract_secrets(self, line: str, line_num: int):
        """Detect secrets - AWS"""
        for match in AWS_ACCESS_KEY.finditer(line):
            self.secrets.append({'type': 'AWS_ACCESS_KEY', 'value': match.group(1)[:10] + '...', 'line': line_num})
        
        for match in AWS_SECRET_KEY.finditer(line):
            self.secrets.append({'type': 'AWS_SECRET_KEY', 'value': match.group(2)[:10] + '...', 'line': line_num})
        
        """Aliyun"""
        for match in ALIYUN_ACCESS_KEY.finditer(line):
            self.secrets.append({'type': 'ALIYUN_ACCESS_KEY', 'value': match.group(2)[:10] + '...', 'line': line_num})
        
        for match in ALIYUN_SECRET_KEY.finditer(line):
            self.secrets.append({'type': 'ALIYUN_SECRET_KEY', 'value': match.group(2)[:10] + '...', 'line': line_num})
        
        """Tencent Cloud"""
        for match in TENCENT_SECRET_ID.finditer(line):
            self.secrets.append({'type': 'TENCENT_SECRET_ID', 'value': match.group(2)[:10] + '...', 'line': line_num})
        
        for match in TENCENT_SECRET_KEY.finditer(line):
            self.secrets.append({'type': 'TENCENT_SECRET_KEY', 'value': match.group(2)[:10] + '...', 'line': line_num})
        
        """Huawei Cloud"""
        for match in HUAWEI_ACCESS_KEY.finditer(line):
            self.secrets.append({'type': 'HUAWEI_ACCESS_KEY', 'value': match.group(2)[:10] + '...', 'line': line_num})
        
        for match in HUAWEI_SECRET_KEY.finditer(line):
            self.secrets.append({'type': 'HUAWEI_SECRET_KEY', 'value': match.group(2)[:10] + '...', 'line': line_num})
        
        """WeChat"""
        for match in WECHAT_APPID.finditer(line):
            self.secrets.append({'type': 'WECHAT_APPID', 'value': match.group(2), 'line': line_num})
        
        for match in WECHAT_APPSECRET.finditer(line):
            self.secrets.append({'type': 'WECHAT_APPSECRET', 'value': match.group(2)[:10] + '...', 'line': line_num})
        
        """WeCom"""
        for match in WECOM_CORP_ID.finditer(line):
            self.secrets.append({'type': 'WECOM_CORP_ID', 'value': match.group(2), 'line': line_num})
        
        for match in WECOM_CORP_SECRET.finditer(line):
            self.secrets.append({'type': 'WECOM_CORP_SECRET', 'value': match.group(2)[:10] + '...', 'line': line_num})
        
        for match in WECOM_AGENT_ID.finditer(line):
            self.secrets.append({'type': 'WECOM_AGENT_ID', 'value': match.group(2), 'line': line_num})
        
        """GitHub"""
        for match in GITHUB_TOKEN.finditer(line):
            self.secrets.append({'type': 'GITHUB_TOKEN', 'value': match.group(0)[:15] + '...', 'line': line_num})
        
        """Slack"""
        for match in SLACK_TOKEN.finditer(line):
            self.secrets.append({'type': 'SLACK_TOKEN', 'value': match.group(0)[:15] + '...', 'line': line_num})
        
        for match in SLACK_WEBHOOK.finditer(line):
            self.secrets.append({'type': 'SLACK_WEBHOOK', 'value': match.group(0)[:50] + '...', 'line': line_num})
        
        """DingTalk"""
        for match in DINGTALK_APP_KEY.finditer(line):
            self.secrets.append({'type': 'DINGTALK_APP_KEY', 'value': match.group(2)[:10] + '...', 'line': line_num})
        
        for match in DINGTALK_SECRET.finditer(line):
            self.secrets.append({'type': 'DINGTALK_SECRET', 'value': match.group(2)[:10] + '...', 'line': line_num})
        
        for match in DINGTALK_WEBHOOK.finditer(line):
            self.secrets.append({'type': 'DINGTALK_WEBHOOK', 'value': match.group(0)[:50] + '...', 'line': line_num})
        
        """Stripe"""
        for match in STRIPE_KEY.finditer(line):
            self.secrets.append({'type': 'STRIPE_KEY', 'value': match.group(0)[:15] + '...', 'line': line_num})
        
        """SendGrid"""
        for match in SENDGRID_API_KEY.finditer(line):
            self.secrets.append({'type': 'SENDGRID_API_KEY', 'value': match.group(0)[:20] + '...', 'line': line_num})
        
        """Twilio"""
        for match in TWILIO_ACCOUNT_SID.finditer(line):
            self.secrets.append({'type': 'TWILIO_ACCOUNT_SID', 'value': match.group(0)[:15] + '...', 'line': line_num})
        
        for match in TWILIO_AUTH_TOKEN.finditer(line):
            self.secrets.append({'type': 'TWILIO_AUTH_TOKEN', 'value': match.group(2)[:10] + '...', 'line': line_num})
        
        """Google"""
        for match in GOOGLE_API_KEY.finditer(line):
            self.secrets.append({'type': 'GOOGLE_API_KEY', 'value': match.group(0)[:20] + '...', 'line': line_num})
        
        """Facebook"""
        for match in FACEBOOK_ACCESS_TOKEN.finditer(line):
            self.secrets.append({'type': 'FACEBOOK_ACCESS_TOKEN', 'value': match.group(0)[:20] + '...', 'line': line_num})
        
        """JWT"""
        for match in JWT_PATTERN.finditer(line):
            self.secrets.append({'type': 'JWT_TOKEN', 'value': match.group(0)[:30] + '...', 'line': line_num})
        
        """MongoDB"""
        for match in MONGO_URI.finditer(line):
            self.secrets.append({'type': 'MONGO_URI', 'value': match.group(0)[:40] + '...', 'line': line_num})
        
        """Redis"""
        for match in REDIS_URI.finditer(line):
            self.secrets.append({'type': 'REDIS_URI', 'value': match.group(0)[:40] + '...', 'line': line_num})
        
        """Private Key"""
        if PRIVATE_KEY_PATTERN.search(line):
            self.secrets.append({'type': 'PRIVATE_KEY', 'line': line_num})
        
        """Generic API Key"""
        for match in API_KEY_PATTERN.finditer(line):
            key_name = match.group(1)
            key_value = match.group(2)
            if len(key_value) > 15:
                self.secrets.append({'type': 'API_KEY', 'key': key_name, 'value': key_value[:12] + '...', 'line': line_num})
    
    def _find_vulnerabilities(self, line: str, line_num: int):
        for sink in XSS_SINKS:
            if sink in line:
                self.vulnerabilities.append({'type': 'XSS', 'sink': sink, 'line': line_num, 'snippet': line.strip()[:80]})
        
        for keyword in SQL_KEYWORDS:
            if f"'{keyword}" in line.lower() or f'"{keyword}' in line.lower():
                if 'where' in line.lower() or 'select' in line.lower():
                    self.vulnerabilities.append({'type': 'SQLI', 'line': line_num, 'snippet': line.strip()[:80]})
                    break
        
        for cmd in CMD_EXEC:
            if cmd in line:
                self.vulnerabilities.append({'type': 'CMD_INJECTION', 'sink': cmd, 'line': line_num, 'snippet': line.strip()[:80]})
    
    def get_results(self) -> dict:
        return {
            'endpoints': sorted(list(self.endpoints)),
            'domains': sorted(list(self.domains)),
            'secrets': self.secrets,
            'vulnerabilities': self.vulnerabilities
        }


def cmd_analyze(args):
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
    analyzer = JSAnalyzer()
    all_results = {'endpoints': set(), 'domains': set(), 'secrets': [], 'vulnerabilities': []}
    
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
    analyzer = JSAnalyzer()
    result = analyzer.analyze_file(args.file)
    for e in result['endpoints']:
        print(e)


def cmd_secrets(args):
    analyzer = JSAnalyzer()
    result = analyzer.analyze_file(args.file)
    for s in result['secrets']:
        print(json.dumps(s, indent=2))


def main():
    parser = argparse.ArgumentParser(description="JS Analyzer - Extract secrets from JS files")
    subparsers = parser.add_subparsers(dest="cmd")
    
    p = subparsers.add_parser("analyze", help="Analyze single file")
    p.add_argument("file")
    p.add_argument("--json", "-j", action="store_true")
    
    p = subparsers.add_parser("scan", help="Scan directory")
    p.add_argument("directory")
    p.add_argument("--json", "-j", action="store_true")
    
    p = subparsers.add_parser("endpoints", help="Extract endpoints")
    p.add_argument("file")
    
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
