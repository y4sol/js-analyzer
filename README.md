# JS Analyzer Skill

> Extract sensitive information from JavaScript files for Red Team/penetration testing.

## Features

- **Endpoint Extraction**: Extract API paths and routes
- **Secret Detection**: 40+ patterns for cloud services and APIs
- **Vulnerability Discovery**: Detect XSS, SQLi, Command Injection sinks
- **Domain Extraction**: Find all domains and URLs
- **Zero Dependencies**: Python standard library only

## Detected Secrets

### Cloud Providers
| Type | Pattern |
|------|---------|
| AWS Access Key | `AKIA...` |
| AWS Secret Key | `aws_secret_access_key` |
| Aliyun (阿里云) | Access Key ID / Secret |
| Tencent Cloud (腾讯云) | Secret ID / Secret Key |
| Huawei Cloud (华为云) | Access Key / Secret |

### WeChat / WeCom
| Type | Pattern |
|------|---------|
| WeChat AppID | `wx...` |
| WeChat AppSecret | 32-char secret |
| WeCom CorpID | 18-char corp ID |
| WeCom CorpSecret | 48-char secret |
| WeCom AgentID | Numeric ID |

### Messaging / Collaboration
| Type | Pattern |
|------|---------|
| Slack Token | `xoxb-...` |
| Slack Webhook | `hooks.slack.com` |
| DingTalk AppKey | `dingtalk_appkey` |
| DingTalk Secret | 40-char secret |
| DingTalk Webhook | `oapi.dingtalk.com` |

### Other Services
| Type | Pattern |
|------|---------|
| GitHub Token | `ghp_...`, `github_token` |
| Stripe Key | `sk_live_...` |
| SendGrid API Key | `SG....` |
| Twilio Account SID | `AC...` |
| Google API Key | `AIza...` |
| Facebook Token | `EAACEdEose0cBA...` |
| JWT Token | `eyJ...` |
| MongoDB URI | `mongodb://` |
| Redis URI | `redis://` |
| Private Key | `-----BEGIN ... PRIVATE KEY-----` |

## Usage

```bash
# Analyze single file
python js_analyzer.py analyze target.js

# Scan directory
python js_analyzer.py scan /path/to/js/files/

# Extract endpoints only
python js_analyzer.py endpoints target.js

# Extract secrets only
python js_analyzer.py secrets target.js

# JSON output
python js_analyzer.py analyze target.js --json
```

## Python Usage

```python
from js_analyzer import JSAnalyzer

analyzer = JSAnalyzer()
result = analyzer.analyze_file("target.js")

print(result['endpoints'])    # List of endpoints
print(result['secrets'])      # List of secrets found
print(result['vulnerabilities'])  # Potential vuln points
```

## Vulnerabilities Detected

- **XSS**: `innerHTML`, `document.write`, `eval()`, `setTimeout()`, `setInterval()`
- **SQLi**: String concatenation in SQL queries
- **CMD Injection**: `exec()`, `spawn()`, `system()`, `child_process`

## License

MIT
