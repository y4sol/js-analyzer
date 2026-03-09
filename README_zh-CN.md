# JS Analyzer 🔍

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-Tool-red.svg)](https://github.com/y4sol/js-analyzer)

*阅读其他语言: [English](README.md)*

强大的 JavaScript 代码分析工具，用于提取敏感信息、发现端点和识别安全漏洞。

## 概述

JS Analyzer 是一款综合性的安全工具，帮助安全研究人员、开发者审计 JavaScript 文件中的潜在安全问题。

### 功能

- **敏感数据提取**：查找硬编码的密钥、API 令牌
- **端点发现**：提取 API 路径、URL 和端点
- **漏洞检测**：识别 XSS、命令注入等问题
- **代码质量分析**：查找调试代码、TODO 注释
- **批量处理**：分析多个文件或目录

⚠️ **免责声明**：本工具仅用于授权的安全测试。扫描任何目标前请务必获得适当授权。

## 功能特性

### 核心能力

| 功能 | 描述 |
|------|------|
| 敏感数据提取 | 查找 API 密钥、令牌、凭据 |
| 端点发现 | 提取 URL 和 API 路径 |
| 漏洞检测 | XSS、命令注入 |
| 多文件支持 | 分析目录 |
| 自定义规则 | 添加自己的检测规则 |
| 多输出格式 | JSON、CSV、控制台输出 |

### 检测类型

| 类别 | 类型 | 模式 |
|------|------|------|
| **云** | AWS Access Key | `AKIA...` |
| **云** | AWS Secret Key | `aws_secret_access_key` |
| **云** | Google API Key | `AIza...` |
| **Git** | GitHub Token | `ghp_...`, `gho_...` |
| **社交** | Slack Token | `xox[baprs]-...` |
| **社交** | Discord Token | `MTE...` |
| **数据库** | MySQL | 连接字符串 |
| **数据库** | PostgreSQL | 连接字符串 |
| **数据库** | MongoDB | URI 模式 |
| **安全** | JWT | Bearer 令牌 |
| **安全** | 私钥 | RSA/DSA/EC |
| **Web** | URL | `http://`, `https://` |
| **Web** | 端点 | `/api/...`, `/v1/...` |
| **漏洞** | XSS | `<script>`, `javascript:` |
| **漏洞** | 命令注入 | `eval()`, `exec()` |

## 安装

### 前置条件

- Python 3.8 或更高版本

### 安装步骤

```bash
# 克隆仓库
git clone https://github.com/y4sol/js-analyzer.git
cd js-analyzer

# 安装依赖
pip install -r requirements.txt

# 验证安装
python scripts/js_analyzer.py --help
```

## 使用方法

### 分析本地文件

```bash
# 分析单个文件
python scripts/js_analyzer.py analyze target.js

# 分析多个文件
python scripts/js_analyzer.py analyze file1.js file2.js

# 分析整个目录
python scripts/js_analyzer.py analyze /path/to/js/files/

# 递归分析
python scripts/js_analyzer.py analyze /path/ --recursive
```

### 扫描网站

```bash
# 扫描网站的 JavaScript
python scripts/js_scanner.py scan https://example.com

# 自定义选项扫描
python scripts/js_scanner.py scan https://example.com --depth 3
```

### 提取特定数据

```bash
# 仅提取端点
python scripts/js_analyzer.py endpoints target.js

# 仅提取密钥
python scripts/js_analyzer.py secrets target.js

# 仅提取 URL
python scripts/js_analyzer.py urls target.js

# 提取特定类型
python scripts/js_analyzer.py secrets target.js --type aws
python scripts/js_analyzer.py secrets target.js --type github
```

### 输出选项

```bash
# JSON 输出
python scripts/js_analyzer.py analyze target.js --format json

# CSV 输出
python scripts/js_analyzer.py analyze target.js --format csv --output results.csv

# 详细输出
python scripts/js_analyzer.py analyze target.js --verbose

# 静默模式（仅结果）
python scripts/js_analyzer.py analyze target.js --quiet
```

### 过滤结果

```bash
# 按严重级别过滤
python scripts/js_analyzer.py analyze target.js --severity critical,high

# 按类型过滤
python scripts/js_analyzer.py analyze target.js --type endpoint,secret
```

## 配置

### 配置文件

编辑 `config/config.json`:

```json
{
  "analysis": {
    "max_file_size": 10485760,
    "encoding": "utf-8",
    "recursive": true,
    "exclude_patterns": [
      "*.min.js",
      "*.bundle.js",
      "node_modules/*"
    ]
  },
  "patterns": {
    "custom_regexes": [],
    "exclude_patterns": []
  },
  "output": {
    "default_format": "console",
    "color": true,
    "verbose": false,
    "show_line_numbers": true
  }
}
```

### 添加自定义规则

```json
{
  "patterns": {
    "custom_regexes": [
      {
        "name": "custom_api_key",
        "pattern": "MY_API_KEY_[A-Z0-9]{16}",
        "severity": "high"
      }
    ]
  }
}
```

## 输出格式

### 控制台输出（默认）

```
[严重] 发现 AWS 密钥
  文件: target.js:42
  行: 42
  值: AKIAIOSFODNN7EXAMPLE

[高危] 发现 GitHub 令牌
  文件: target.js:100
  行: 100
  值: ghp_xxxxxxx

[中等] 发现 API 端点
  文件: target.js:150
  行: 150
  值: https://api.example.com/v1/users
```

### JSON 输出

```json
{
  "findings": [
    {
      "type": "aws_key",
      "severity": "critical",
      "file": "target.js",
      "line": 42,
      "value": "AKIAIOSFODNN7EXAMPLE"
    }
  ],
  "summary": {
    "total": 10,
    "critical": 2,
    "high": 3,
    "medium": 4,
    "low": 1
  }
}
```

### CSV 输出

```csv
severity,type,file,line,value
critical,aws_key,target.js,42,AKIAIOSFODNN7EXAMPLE
high,github_token,target.js,100,ghp_xxxxxxx
```

## 检测规则

### 严重级别

| 级别 | 颜色 | 示例 |
|------|------|------|
| Critical | 红色 | 私钥、数据库凭据 |
| High | 橙色 | API 密钥、令牌、密码 |
| Medium | 黄色 | 端点、内部 URL |
| Low | 蓝色 | 调试语句、注释 |

### 模式类别

#### 1. 云凭据

```javascript
// AWS Access Key
AKIAIOSFODNN7EXAMPLE

// AWS Secret Key
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

#### 2. 身份验证令牌

```javascript
// GitHub Token
ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

// Slack Token
xoxb-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

#### 3. 数据库凭据

```javascript
// MySQL
mysql://user:password@localhost:3306/db

// MongoDB
mongodb://admin:password@localhost:27017/db
```

#### 4. API 端点

```javascript
// REST API
https://api.example.com/v1/users
/api/auth/login
```

#### 5. 安全问题

```javascript
// XSS
<script>alert(1)</script>

// 命令注入
eval(userInput)
exec(systemCommand)
```

## 使用示例

### 基本分析

```bash
# 简单扫描
python scripts/js_analyzer.py analyze login.js

# 仅查找密钥
python scripts/js_analyzer.py secrets auth.js

# 仅查找端点
python scripts/js_analyzer.py endpoints app.js
```

### 高级用法

```bash
# 扫描整个项目
python scripts/js_analyzer.py analyze ./src/ --recursive

# 导出为 JSON
python scripts/js_analyzer.py analyze app.js --format json --output findings.json

# 仅过滤严重问题
python scripts/js_analyzer.py analyze app.js --severity critical
```

### 网站扫描

```bash
# 扫描网站
python scripts/js_scanner.py scan https://example.com

# 深度扫描
python scripts/js_scanner.py scan https://example.com --depth 5
```

## 目录结构

```
js-analyzer/
├── scripts/
│   ├── js_analyzer.py         # 主分析工具
│   └── js_scanner.py          # 网站扫描器
├── config/
│   └── config.json            # 配置文件
├── tests/
│   ├── test_js.py             # 单元测试
│   └── __init__.py
├── SKILL.md                   # Skill 文档
├── SPEC.md                    # 规范说明
├── README.md                  # English version
├── README_zh-CN.md           # 中文版本
├── requirements.txt           # 依赖
└── .gitignore                # Git 忽略规则
```

## 已知限制

- 无法解密混淆代码
- 可能遗漏动态生成的密钥
- 某些模式可能产生误报
- 对高度混淆的代码效果不佳

## 最佳实践

### 扫描前

1. **排除不必要的文件**
   ```json
   "exclude_patterns": ["*.min.js", "node_modules/*"]
   ```

2. **设置文件大小限制**
   ```json
   "max_file_size": 10485760
   ```

### 扫描后

1. **手动验证每个发现**
2. **从未来扫描中移除误报**
3. **记录修复步骤**

## 故障排除

### 无结果

- 检查文件编码（建议 UTF-8）
- 尝试使用 `--verbose` 标志
- 验证文件不为空

### 结果过多

- 使用 `--severity` 过滤
- 添加排除模式
- 使用 `--type` 过滤

### 性能问题

- 减少网站扫描的 `--depth`
- 排除大文件
- 使用 `--quiet` 加快输出

## 法律声明

⚠️ **重要**：本工具仅用于：

1. 授权的安全测试
2. 教育目的
3. 个人安全研究
4. DevSecOps 集成

**请勿**用于：

- 未经授权的扫描
- 未经许可利用漏洞
- 访问非您拥有的系统
- 任何非法活动

请始终遵守您管辖区的适用法律法规。

## 许可证

MIT 许可证 - 详见 [LICENSE](LICENSE)。
