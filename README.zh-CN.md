<div align="center">

# RAGShield

**面向 RAG 应用的防御性安全评测平台**

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)
![Vue](https://img.shields.io/badge/Vue-3-42b883)
![Coverage](https://img.shields.io/badge/coverage-94%25-63f5b1)
![License](https://img.shields.io/badge/license-MIT-63f5b1)

</div>

[English](README.md) · 简体中文

RAGShield 将 Prompt Injection、RAG 知识库投毒、跨租户越权、敏感信息泄露
与引用完整性转化为可重复执行的安全控制，输出证据、修复建议和加权安全评分。

默认模式完全离线：不访问网络、不需要模型 API Key，只运行内置的脆弱与加固
RAG 基线。服务端管理员也可以通过精确域名白名单，接入经过授权的测试环境。

## 核心能力

- 6 项内置控制，覆盖 5 类 RAG 攻击面；
- OWASP LLM 与 MITRE ATLAS 威胁映射；
- 一键对比脆弱/加固基线并计算安全收益；
- 受控 HTTP 目标接入，默认防范 SSRF 与任意网络扫描；
- Markdown、JSON、SARIF 三种报告；
- 可在 GitHub Code Scanning 中展示检测结果；
- 数据化自定义规则包，不加载第三方 Python 代码；
- CLI 严重性退出码，可作为 CI 安全门禁；
- FastAPI、Vue 3、SQLite、Docker Compose、自动测试与 CI。

## 一分钟运行

```bash
docker compose up --build
```

访问 `http://localhost:8080`，API 文档位于 `http://localhost:8000/docs`。

不使用 Docker 时，可以分别启动后端与前端：

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload
```

```bash
cd frontend
npm install
npm run dev
```

## CLI 与 CI

```bash
cd backend
pip install .
ragshield --profile demo-vulnerable --format sarif --output ragshield.sarif
```

默认情况下，发现高危或严重问题时 CLI 返回状态码 `1`；配置错误返回 `2`；
策略通过返回 `0`。可使用 `--fail-on` 调整 CI 门禁等级。

## 接入自己的 RAG 系统

网络目标必须由服务端管理员显式启用：

```bash
RAGSHIELD_ENABLE_NETWORK_TARGETS=true
RAGSHIELD_HTTP_TARGET_ALLOWLIST=rag-staging.example.com
```

RAGShield 只允许访问精确白名单中的主机，并默认执行 DNS/IP 检查、禁止重定向、
禁止环境代理、限制响应大小与超时时间。完整协议请查看
[HTTP 接入指南](docs/HTTP_INTEGRATION.md)。

## 自定义规则

```bash
ragshield --profile demo-hardened \
  --control-pack examples/control-pack.json \
  --format json
```

规则包采用受限制的 JSON 数据格式，不执行插件代码。详细字段说明见
[自定义规则包](docs/CONTROL_PACKS.md)。

## 安全边界

本项目仅用于评测你拥有或得到明确授权的系统。RAGShield 不提供任意互联网扫描器；
演示密钥均为不可用的测试字符串。通过某个控制只代表该确定性场景通过，不等同于
安全认证或对自适应攻击者的完整防护。

架构与限制请参阅[架构文档](docs/ARCHITECTURE.md)和
[威胁模型](docs/THREAT_MODEL.md)。安全问题请按照 [SECURITY.md](SECURITY.md)
私下报告。

项目采用 [MIT License](LICENSE) 开源，欢迎提交安全控制、适配器、测试和文档改进。

