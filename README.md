# JS Analyzer Skill

> Extract sensitive information from JavaScript files for Red Team/penetration testing.

## Tools

1. **js_analyzer.py** - Analyze local JS files
2. **js_scanner.py** - Crawl website and analyze all JS files

---

## js_scanner.py - Web Scanner

Crawl a website and analyze all JavaScript files for secrets.

### Usage

```bash
# Scan website for secrets
python js_scanner.py scan https://example.com

# Verbose output
python js_scanner.py scan https://example.com -v

# JSON output
python js_scanner.py scan https://example.com --json

# Just list JS files
python js_scanner.py crawl https://example.com
```

### Features

- Auto-extract all JS files from website
- Analyze inline scripts
- Support for 20+ secret types
- Detect XSS/CMD injection vulnerabilities

---

## js_analyzer.py - Local Analyzer

Analyze local JavaScript files.

### Usage

```bash
# Analyze single file
python js_analyzer.py analyze target.js

# Scan directory
python js_analyzer.py scan /path/to/js/

# Extract endpoints only
python js_analyzer.py endpoints target.js

# Extract secrets only
python js_analyzer.py secrets target.js

# JSON output
python js_analyzer.py analyze target.js --json
```

---

## Detected Secrets

### Cloud Providers
| Type | Pattern |
|------|---------|
| AWS Access Key | `AKIA...` |
| AWS Secret Key | `aws_secret_access_key` |
| Aliyun (阿里云) | Access Key / Secret |
| Tencent Cloud (腾讯云) | Secret ID / Key |

### WeChat / WeCom
| Type | Pattern |
|------|---------|
| WeChat AppID | `wx...` |
| WeChat AppSecret | 32-char |
| WeCom CorpID | 18-char |
| WeCom CorpSecret | 48-char |
| WeCom AgentID | Numeric |

### Other Services
| Type | Pattern |
|------|---------|
| GitHub Token | `ghp_...` |
| Slack Token | `xoxb-...` |
| Slack Webhook | `hooks.slack.com` |
| DingTalk Webhook | `oapi.dingtalk.com` |
| Stripe Key | `sk_live_...` |
| Google API Key | `AIza...` |
| JWT Token | `eyJ...` |
| MongoDB URI | `mongodb://` |
| Redis URI | `redis://` |
| Private Key | `-----BEGIN ... PRIVATE KEY-----` |

---

## Vulnerabilities Detected

- **XSS**: `innerHTML`, `document.write`, `eval()`, `setTimeout()`
- **CMD Injection**: `exec()`, `spawn()`, `system()`, `child_process`

---

## License

MIT
