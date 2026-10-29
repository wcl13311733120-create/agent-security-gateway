# Agent Security Gateway

**OpenAI 兼容的双层防护代理网关** — Policy-as-Code、提示词注入防护、HITL 审批、全链路审计日志。

可对接 [QuotaRouter](../quota-router/) 构建 **Agent Security Gateway → QuotaRouter → Upstream Providers** 的双层防护链路。

## 特性

### 第一层：安全防护
- **Policy-as-Code**：基于 Action Catalog 的访问控制，动态管理允许的操作
- **提示词注入防护**：内置拦截常见注入模式（`DROP TABLE`、`rm -rf /`、`ignore previous instructions` 等）
- **动态黑名单**：Web 仪表盘或 API 实时增删拦截模式，无需重启服务
- **HITL Approval**：Human-in-the-loop 审批钩子，拦截请求可进入人工审批流程
- **全链路审计日志**：记录每个请求的决策、拦截原因、上游响应

### 第二层：配额与韧性（通过 QuotaRouter）
- **配额感知路由**：实时 RPM/TPM 滑动窗口统计，智能选优
- **毫秒级故障转移**：自动熔断 429/503/超时，平滑切换备用节点
- **多路由策略**：`quota_aware` / `priority` / `low_latency`
- **Web 监控大屏**：供应商健康、配额进度、审计日志实时展示

## 架构

```
┌──────────┐     ┌─────────────────────────┐     ┌──────────────────┐     ┌──────────────┐
│  Client  │ ──▶ │ Agent Security Gateway  │ ──▶ │  QuotaRouter     │ ──▶ │ Upstream     │
│          │     │ (127.0.0.1:8738)        │     │ (127.0.0.1:18090)│     │ Providers    │
│ OpenAI   │     │ • Policy Engine         │     │ • Quota-Aware    │     │ (DeepSeek/Kimi│
│ API 格式 │     │ • Injection Filter      │     │  /Free Pool)  │
└──────────┘     │ • HITL Gate             │     │ • Circuit Breaker│     └──────────────┘
                  │ • Audit Logger          │
                  │ • Metrics Tracker       │
                  └─────────────────────────┘
```

## 快速开始

### 1. 启动 QuotaRouter（上游路由层）
```bash
cd ../quota-router
python3 gateway.py config.json 18090
```

### 2. 启动 Agent Security Gateway（安全防护层）
```bash
cd ../agent-security-gateway
python3 main.py
```

服务启动后：
- **Web 安全仪表盘**：http://127.0.0.1:8738/
- **OpenAI 代理端点**：http://127.0.0.1:8738/v1/chat/completions
- **模型列表**：http://127.0.0.1:8738/v1/models
- **状态 API**：http://127.0.0.1:8738/api/status
- **审计日志 API**：http://127.0.0.1:8738/api/audit

### 3. 测试双层防护
```bash
# 正常请求（通过安全检查后转发到 QuotaRouter）
curl -X POST http://127.0.0.1:8738/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "deepseek-chat", "messages": [{"role": "user", "content": "Hello"}]}'

# 注入攻击测试（安全网关直接拦截）
curl -X POST http://127.0.0.1:8738/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "deepseek-chat", "messages": [{"role": "user", "content": "DROP TABLE users;"}]}'
```

## API 接口

| 端点 | 方法 | 说明 |
|------|------|------|
| `/` | GET | Web 安全仪表盘 |
| `/v1/chat/completions` | POST | OpenAI 兼容聊天接口（受策略保护） |
| `/v1/models` | GET | 模型列表接口（受策略保护） |
| `/api/status` | GET | 实时指标（请求数、拦截数、成功率、策略状态） |
| `/api/audit` | GET | 审计日志（`?limit=N`） |
| `/api/policy/actions` | GET/POST/PUT | 管理允许的操作集 |
| `/api/policy/blocked-patterns` | GET/POST/PUT/DELETE | 管理黑名单模式（动态生效） |

## 配置

在 `main.py` 中修改配置：

```python
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8738
UPSTREAM_URL = "http://localhost:18090/v1"  # 对接 QuotaRouter

# 默认允许操作
ALLOWED_ACTIONS_DEFAULT = {"chat-messages:invoke", "models:list", "chat-messages:stream"}

# 默认拦截模式
BLOCKED_PATTERNS_DEFAULT = [
    "DROP TABLE", "rm -rf /", "ignore previous instructions",
    "disregard your rules", "<script>"
]
```

## 测试

```bash
python3 -m unittest test_gateway.py -v
# Ran 14 tests in 0.001s - OK
```

## 文件结构

```
agent-security-gateway/
├── main.py          # 核心网关（Policy Engine + Proxy + Dashboard）
├── test_gateway.py  # 单元测试套件（14 个测试用例）
└── README.md        # 项目文档
```

## 安全说明

- **MVP 版本**：当前采用内存存储策略和指标，重启后恢复默认配置
- **HITL 默认自动批准**：生产环境需接入真实审批系统（Slack/Email/工单）
- **本地绑定**：默认仅监听 `127.0.0.1`，生产环境需配合反向代理和 TLS
- **纯标准库**：零第三方依赖，便于审计和安全评估
