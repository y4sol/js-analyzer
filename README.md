# JS Analyzer Skill

> Extract sensitive information from JavaScript files for Red Team/penetration testing.

## Features

- **Endpoint Extraction**: Extract API paths and routes
- **Secret Detection**: Find API keys, tokens, AWS keys, JWT
- **Vulnerability Discovery**: Detect XSS, SQLi, Command Injection sinks
- **Domain Extraction**: Find all domains and URLs
- **Zero Dependencies**: Python standard library only

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

## Detected Patterns

### Secrets
- AWS Access Keys
- JWT Tokens
- API Keys / Tokens
- Private Keys

### Vulnerabilities
- XSS: `innerHTML`, `document.write`, `eval()`
- SQL Injection: String concatenation in queries
- Command Injection: `exec()`, `spawn()`, `system()`

## License

MIT
