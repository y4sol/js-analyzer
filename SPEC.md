# JS Analyzer Skill Specification

## 功能目标
从 JavaScript 文件中提取敏感信息，用于 Web 渗透测试。

## 核心功能

### 1. 端点提取
- 提取 URL 路径 (`/api/*`, `/admin/*`)
- 提取 API 路由
- 提取 AJAX/Fetch 请求

### 2. 敏感信息检测
- API Keys / Tokens
- AWS Keys
- Private Keys
- Hardcoded Passwords
- JWT Tokens

### 3. 潜在漏洞点
- `eval()`, `innerHTML` (XSS)
- `document.write()` (XSS)
- SQL 语句拼接
- 命令执行 (`exec`, `spawn`, `system`)

### 4. 域名提取
- 提取所有域名
- 提取内网 IP

## 使用方式

```bash
# 分析单个文件
python js_analyzer.py analyze <file.js>

# 分析目录
python js_analyzer.py scan <directory/>

# 提取端点
python js_analyzer.py endpoints <file.js>

# 提取敏感信息
python js_analyzer.py secrets <file.js>
```

## 技术实现

- 正则表达式匹配
- 无外部依赖 (Python 标准库)
- 支持大文件流式处理
- 支持压缩 JS (minified)

## 输出格式

```json
{
  "endpoints": ["/api/login", "/admin/config"],
  "secrets": [{"type": "AWS_KEY", "value": "xxx", "line": 10}],
  "domains": ["api.target.com"],
  "vulnerabilities": [{"type": "XSS", "sink": "innerHTML", "line": 25}]
}
```
