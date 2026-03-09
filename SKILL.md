---
name: js-analyzer
description: 从 JavaScript 文件和网站中提取敏感信息（端点、密钥、漏洞）。使用语义边界清晰的词汇，确保输出可控。
author: y4sol
version: 1.0.0
tags:
  - red-team
  - recon
  - osint
  - web
capabilities:
  - none

---

# JS 代码分析

## ⚠️ 语义边界声明

本 Skill 仅执行以下**明确限定**的操作：

1. **列出 (list)** - 列出发现的端点
2. **提取 (extract)** - 提取敏感信息（密钥、Token、URL）
3. **检测 (detect)** - 检测特定模式

**不执行**：
- ❌ 不进行"分析"（语义过宽）
- ❌ 不给出"建议"（超出范围）
- ❌ 不做"评估"（主观判断）
- ❌ 不输出"风险等级"（自行发明）

## 📋 结构化工作流

```
STEP 1: 确定目标 (文件或网站)
STEP 2: 选择操作类型 (端点提取/密钥提取/模式检测)
STEP 3: 执行提取
STEP 4: 格式化输出结果
```

每一步都有明确的**输入 → 执行 → 输出**，不允许跳过。

## 🔧 强制输出格式

输出必须严格按以下 JSON 格式，禁止自行添加"分析"、"建议"等内容：

```json
{
  "type": "endpoints|secrets|patterns",
  "count": 0,
  "results": [
    {
      "url": "https://api.example.com/v1/user",
      "method": "GET",
      "line": 10
    }
  ]
}
```

## 🎯 词汇选择（避免语义陷阱）

| ❌ 禁用词汇 | ✅ 替换为 |
|-----------|----------|
| 分析 | 提取/列出 |
| 评估 | - (不输出) |
| 建议 | - (不输出) |
| 风险 | - (不输出) |
| 描述 | 列出 |

## 🔧 工具命令

### 本地文件分析

```bash
# 提取端点
python scripts/js_analyzer.py endpoints target.js

# 提取敏感信息
python scripts/js_analyzer.py secrets target.js

# 模式检测
python scripts/js_analyzer.py analyze target.js

# 目录扫描
python scripts/js_scanner.py scan /path/to/dir
```

### 网站扫描

```bash
# 网站 JS 扫描
python scripts/js_scanner.py scan https://example.com
```

## 支持的类型

| 类型 | 说明 | 输出 |
|-----|------|-----|
| endpoints | API 端点 | URL + Method |
| secrets | 敏感信息 (API Key, Token, URL) | 类型 + 值 |
| analyze | 通用分析 | 模式匹配结果 |

## 敏感信息检测范围

仅检测以下**明确定义**的类型：

- AWS Access Key
- GitHub Token
- API Key / Token
- 微信 OpenID / UnionID
- 内部 URL
- 硬编码密码

**不检测**（语义过宽）：
- 代码格式问题
- 性能问题
- 架构建议
