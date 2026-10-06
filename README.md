<div align="center">

# RAGShield

**面向 RAG 应用的开源防御性安全评测平台**

[![CI](https://github.com/carb6661/ragshield/actions/workflows/ci.yml/badge.svg)](https://github.com/carb6661/ragshield/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)
![Vue](https://img.shields.io/badge/Vue-3-42b883)
![Coverage](https://img.shields.io/badge/coverage-94%25-63f5b1)
![License](https://img.shields.io/badge/license-MIT-63f5b1)

[English](README.en.md) · 简体中文

</div>

RAGShield 将 Prompt Injection、RAG 知识库投毒、跨租户越权、敏感信息泄露
和引用完整性转化为可重复执行的安全控制，并输出检测证据、修复建议和加权安全评分。

项目默认以**本地安全模式**运行：不访问外部网络、不需要模型 API Key、不加载
第三方插件代码。只有服务端管理员显式启用精确域名白名单后，才能评测经过授权的
HTTP 测试目标。

> RAGShield 仅用于评测你拥有或获得明确授权的系统。它不是任意互联网扫描器，
> 也不构成合规认证或安全保证。

## 为什么使用 RAGShield

- **面向真实 RAG 风险**：覆盖直接提示词注入、检索内容投毒、租户隔离、PII 与密钥泄露、答案溯源。
- **安全默认值**：网络目标默认关闭；启用后仍受精确白名单、DNS/IP、重定向、代理、超时和响应大小限制。
- **可接入工程流程**：提供 CLI、严重性退出码、JSON/SARIF 报告和 GitHub Code Scanning 集成。
- **结果可解释**：每项控制包含证据、严重性、OWASP/MITRE 映射与修复建议。
- **便于扩展**：组织可使用受限制的 JSON 规则包增加内部控制，不执行外部 Python 代码。
- **完整开源工程**：包含前后端、测试、Docker、CI、威胁模型、安全策略、贡献指南和 Issue 模板。

## 功能概览

| 能力 | 说明 |
|---|---|
| 本地基线 | 内置脆弱版与加固版 RAG 靶场，无需模型或网络 |
| 安全控制 | 6 项内置控制，覆盖 5 类攻击面 |
| 基线对比 | 一键执行两套基线，计算加固前后安全收益 |
| 授权 HTTP 目标 | 仅访问服务端管理员配置的精确白名单主机 |
| 报告 | Markdown、JSON、SARIF |
| CLI | 支持 CI 门禁、自定义规则包和文件输出 |
| Web 控制台 | 安全态势、风险分类、证据详情、扫描历史、移动端布局 |
| 安全框架 | OWASP LLM Top 10、MITRE ATLAS |

## 内置控制

| ID | 类别 | 测试场景 | 严重性 |
|---|---|---|---|
| PI-001 | Prompt Injection | 隐藏系统策略提取 | 高危 |
| RAG-001 | RAG Poisoning | 检索文档中的恶意指令 | 严重 |
| ACL-001 | Access Control | 跨租户文档读取 | 严重 |
| PII-001 | Data Leakage | 个人信息泄露 | 高危 |
| SEC-001 | Data Leakage | 凭据与密钥外泄 | 严重 |
| SRC-001 | Integrity | 回答缺少可验证来源 | 中危 |

## 一分钟启动

### Docker Compose

```bash
docker compose up --build
```

启动后访问：

- Web 控制台：`http://127.0.0.1:8080`
- API 文档：`http://127.0.0.1:8000/docs`

默认端口只绑定到本机回环地址，不向局域网公开。停止并删除容器：

```bash
docker compose down
```

如需同时删除本地扫描历史卷：

```bash
docker compose down -v
```

### 本地开发

后端：

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload --host 127.0.0.1
```

前端：

```bash
cd frontend
npm install
npm run dev -- --host 127.0.0.1
```

## CLI 使用

```bash
cd backend
pip install .
ragshield --profile demo-vulnerable --format sarif --output ragshield.sarif
```

先查看内置控制，而不连接任何目标：

```bash
ragshield --list-controls
```

用内置靶场做一次 30 秒演示（不会访问网络）：

```bash
ragshield --profile demo-vulnerable --format markdown --fail-on never
ragshield --profile demo-hardened --format markdown --fail-on never
```

两次输出可直观展示相同控制在脆弱配置与加固配置下的差异，适合在本地评估流程或 CI 试运行中使用。

CLI 退出码：

- `0`：没有达到门禁阈值的失败项；
- `1`：检测到达到 `--fail-on` 阈值的问题，默认阈值为 `high`；
- `2`：参数、目标或规则包配置错误。

仅观察、不阻断 CI：

```bash
ragshield --profile demo-vulnerable --fail-on never
```

## API 示例

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_name":"Local lab","target_profile":"demo-vulnerable"}'
```

报告下载：

```text
GET /api/v1/scans/{scan_id}/report?format=markdown
GET /api/v1/scans/{scan_id}/report?format=json
GET /api/v1/scans/{scan_id}/report?format=sarif
```

## 接入经过授权的 RAG 测试环境

网络目标默认关闭。服务端管理员必须同时启用功能并配置精确域名白名单：

```bash
RAGSHIELD_ENABLE_NETWORK_TARGETS=true
RAGSHIELD_HTTP_TARGET_ALLOWLIST=rag-staging.example.com
```

默认只接受 HTTPS 和公网地址，并执行以下限制：

- 禁止 URL 内嵌用户名和密码；
- 禁止 HTTP 重定向；
- 禁止读取系统环境代理；
- DNS 解析结果默认必须为公网地址；
- 限制请求超时与响应体大小；
- Bearer Token 只存在于当前请求内，不写入数据库；
- 浏览器用户不能自行扩大目标白名单。

完整请求协议与部署注意事项见 [HTTP 接入指南](docs/HTTP_INTEGRATION.md)。

## 自定义控制包

```bash
ragshield --profile demo-hardened \
  --control-pack examples/control-pack.json \
  --format json
```

规则包采用受限制的 JSON 格式，最大 256 KB、最多 100 项控制，不执行插件代码。
字段说明见 [自定义控制包](docs/CONTROL_PACKS.md)。

## CI 集成

```yaml
- name: Run RAGShield
  working-directory: backend
  run: |
    pip install .
    ragshield --profile demo-hardened --format sarif --output ragshield.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: backend/ragshield.sarif
```

生产或测试凭据应存放在 CI Secret 中，不要写入仓库、规则包或命令历史。

## 项目结构

```text
ragshield/
├── backend/                 # FastAPI、扫描引擎、CLI、测试
├── frontend/                # Vue 3 安全控制台
├── docs/                    # 架构、威胁模型、HTTP 与规则包文档
├── examples/                # 不含真实凭据的本地示例
├── .github/                 # CI、Issue 与 PR 模板
├── docker-compose.yml
├── SECURITY.md
├── CONTRIBUTING.md
└── LICENSE
```

## 安全与本机影响

默认配置不会访问外部 RAG 服务，不读取浏览器、SSH、Git 或云平台凭据，也不会修改
GitHub/Gitee 账号。项目只会在仓库目录、Python 虚拟环境或 Docker 命名卷中写入数据。

| 项目 | 默认行为 |
|---|---|
| 网络扫描 | 关闭 |
| 模型/API Key | 不需要 |
| 本机文件挂载 | 无 |
| Docker 特权模式 | 未启用 |
| Web 端口 | 仅绑定 `127.0.0.1` |
| 扫描历史 | SQLite，本地文件或 Docker 命名卷 |
| 演示数据 | 明确标记的不可用测试字符串 |
| 账号操作 | 不登录、不创建仓库、不推送代码 |

启用授权 HTTP 目标、把服务暴露给其他设备或向代码托管平台推送，均属于管理员主动
操作，不是默认行为。详细分析见 [威胁模型](docs/THREAT_MODEL.md)和
[安全策略](SECURITY.md)。

## 开发与验证

```bash
cd backend
ruff check app tests ../examples
pytest --cov=app

cd ../frontend
npm audit
npm run build
```

当前后端测试覆盖率为 94%。

## 贡献

欢迎贡献新的安全控制、框架适配器、测试、文档和误报优化。提交前请阅读
[贡献指南](CONTRIBUTING.md)与[行为准则](CODE_OF_CONDUCT.md)。

安全漏洞请不要创建公开 Issue，请按照 [SECURITY.md](SECURITY.md) 私下报告。

## 路线图

- 签名和版本化的社区控制包；
- 确定性标记之外的可插拔语义评测器；
- 定时回归扫描与安全评分趋势；
- 更多 RAG 框架与认证方式适配器；
- 中英文控制台与报告。

## 许可证

项目采用 [MIT License](LICENSE) 开源。
