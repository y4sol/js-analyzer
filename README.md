# JS Analyzer 🔍

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)

*Read this in other languages: [中文](README_zh-CN.md)*

A powerful JavaScript code analysis tool for security testing.

## Overview

JS Analyzer helps security researchers analyze JavaScript files for:
- Sensitive information (API keys, tokens)
- Security vulnerabilities
- Code quality issues

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Analyze file
python scripts/js_analyzer.py analyze target.js

# Find secrets
python scripts/js_analyzer.py secrets target.js

# Find endpoints
python scripts/js_analyzer.py endpoints target.js
```

## Features

- Multiple detection patterns
- JSON/CSV output
- Custom rules support

## Directory Structure

```
├── scripts/
├── config/
├── tests/
├── README.md
└── requirements.txt
```

## License

MIT
