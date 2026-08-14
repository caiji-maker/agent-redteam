---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '2ca829ec-5eda-424a-8eab-13a698094649'
  PropagateID: '2ca829ec-5eda-424a-8eab-13a698094649'
  ReservedCode1: '766590ba-1bde-4b5c-a45e-717519313200'
  ReservedCode2: '766590ba-1bde-4b5c-a45e-717519313200'
---

# AgentRedTeam

AI Agent 安全攻防测试平台 v0.5.0

间接注入 · 直接注入 · 越狱攻击 · 工具滥用 · 多轮对话 · Prompt 泄露 · 工具返回值注入 · 角色冒充/权限提升 · 紧急性操纵 · 意图劫持 · 工具链攻击

## 是什么

AgentRedTeam 是一个面向 AI Agent 系统的自动化红队测试平台。它通过模拟真实攻击者的手法，系统性发现 Agent 的安全漏洞，并以**对比测试**量化防护效果——单独测 LLM 没有意义，有防护 vs 无防护的攻击成功率差值才是防护层的真实效果。

核心思路：当大量用户使用 AI Agent 时，Agent 本身成为高价值攻击面。本平台测的是用户自己的 Agent 配置（system prompt + 安全校验 + 工具权限）有没有用，必须做对比测试，差值才是防护层的真实效果。

## 功能

### 11 种攻击类型，130+ 载荷变体

| 攻击类型         | 载荷数   | 说明                            |
| ------------ | ----- | ----------------------------- |
| 间接 Prompt 注入 | 10 变体 | 恶意指令藏在邮件/文档/网页中，Agent 解析时无意执行 |
| 直接注入         | 16 条  | 直白恶意请求，测试 Agent 对明文攻击的防护      |
| 越狱攻击         | 17 条  | 角色扮演/奶奶漏洞/逻辑陷阱等绕过安全规则         |
| 工具滥用链        | 3 链路  | 合法工具组合实现恶意效果（邮件->URL->下载->执行） |
| 多轮对话攻击       | 8 场景  | 逐步诱导，每轮无害，最后一轮收网              |
| Prompt 泄露    | 24 条  | 套出 Agent 的 system prompt      |
| 工具返回值注入      | 7 场景  | 工具返回值中藏入指令，Agent 读取后当作新指令执行   |
| 角色冒充/权限提升    | 18 条  | 冒充管理员/开发者/运维等高权限角色执行危险操作      |
| 紧急性操纵        | 17 条  | 制造虚假紧急场景迫使 Agent 绕过安全检查       |
| 意图劫持         | 14 条  | 篡改用户原始意图的执行方向，偏离到危险操作         |
| 工具链攻击        | 13 条  | 组合多个无害工具调用构成完整攻击链             |

### 核心能力

- **对比测试**：选择任意两种防护等级对比，量化防护改善效果
- **攻击链回放**：逐步回放完整攻击过程（System Prompt -> 攻击载荷 -> LLM 决策 -> 工具调用 -> 拦截/执行），三种播放模式（自动/单步/全部展开）
- **多模型批量对比**：同时测试多个模型，表格横向对比安全性，最优模型星标高亮
- **自定义工具定义**：在界面上填写自己的工具名、参数、敏感类别，替代内置 6 个默认工具
- **工具调用证据链**：不只是工具名，展示 LLM 的完整 tool_calls 参数（名称+参数+是否被拦截+模拟返回值）
- **Judge LLM 语义评审**：用另一个 LLM 对攻击结果做语义评分，减少正则匹配误判
- **误判校准**：原始成功率 vs 校准成功率，手动调整对比
- **实时进度**：异步并发 + WebSocket 推送，分钟级完成全量测试
- **网络错误处理**：自动检测本地代理，连接超时快速失败，网络错误单独统计不计入成功率
- **修复建议**：根据攻击结果自动生成针对性修复方案
- **趋势分析**：历次测试成功率变化，回归风险标记
- **载荷外部化**：YAML 载荷文件 + 热重载，支持自定义载荷
- **报告导出**：Markdown / JSON 格式

## 快速开始

### 1. 安装依赖

```bash
cd agent-redteam
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/macOS
pip install -e .
```

### 2. 启动服务

```bash
# 方式一：启动脚本（Windows）
start.bat

# 方式二：手动启动
.venv\Scripts\python -m uvicorn web.server:app --host 127.0.0.1 --port 8000
```

### 3. 打开浏览器

访问 http://127.0.0.1:8000

- 填写 API Key（支持 DeepSeek / OpenAI / 通义千问 / GLM / Moonshot / 百川 / 硅基流动等 OpenAI 兼容接口）
- 选择防护等级和攻击类型
- 点击「开始测试」

## 项目结构

```
agent-redteam/
├── src/agent_redteam/
│   ├── models.py           # 数据模型（AttackType / Payload / SecurityBaseline）
│   ├── generator.py        # 攻击载荷生成器（间接注入 + 工具滥用）
│   ├── monitor.py          # 行为监控器
│   ├── scorer.py           # 风险评分器
│   ├── sandbox.py          # 行为沙箱
│   ├── base_agent.py       # Agent 基类
│   ├── demo_agent.py       # Demo Agent（模拟 LLM 工具调用决策）
│   ├── reporter.py         # Markdown 报告生成器
│   └── cli.py              # CLI 入口
├── web/
│   ├── server.py           # FastAPI 后端（v0.5.0）
│   └── index.html          # 前端单页应用（v0.5.0）
├── payloads/               # YAML 载荷文件
│   ├── direct_injection.yaml
│   ├── jailbreak.yaml
│   ├── prompt_leak.yaml
│   ├── tool_output_injection.yaml
│   ├── multi_turn.yaml
│   ├── role_privilege_escalation.yaml
│   ├── urgency_manipulation.yaml
│   ├── intent_hijacking.yaml
│   ├── tool_chain_attack.yaml
│   └── custom/             # 自定义载荷目录
├── examples/               # 使用示例
├── start.bat               # 一键启动脚本
└── pyproject.toml          # 项目配置（v0.5.0）
```

## 防护等级

| 等级  | 防护内容                                              |
| --- | ------------------------------------------------- |
| 无防护 | 仅"你是一个助手"，作为对比基线                                  |
| 低级  | 基础 system prompt                                  |
| 中级  | 加强 prompt + 输入检测                                  |
| 高级  | 加强 prompt + 输入检测 + 工具权限 + URL 白名单 + 文件路径检查 + 邮件限制 |
| 自定义 | 自定义 system prompt + 5 个安全开关                       |

## API

| 端点                          | 方法        | 说明                          |
| --------------------------- | --------- | --------------------------- |
| `/api/models`               | GET       | 预设模型列表（18 个）                 |
| `/api/protection`           | GET       | 防护等级列表                      |
| `/api/attack-types`         | GET       | 攻击类型及变体                     |
| `/api/payloads`             | GET       | 已加载载荷信息                     |
| `/api/payloads/reload`      | POST      | 热重载 YAML 载荷                 |
| `/api/test`                 | POST      | 启动测试                        |
| `/api/test/{id}`            | GET       | 获取测试结果                      |
| `/api/test/{id}/report`     | GET       | 导出报告（?format=markdown/json） |
| `/api/test/{id}/replay/{idx}` | GET     | 获取单条击穿记录的攻击链回放数据             |
| `/api/batch-compare`        | POST      | 多模型批量对比                     |
| `/api/history`              | GET       | 历史测试记录                      |
| `/ws/{test_id}`             | WebSocket | 实时进度推送                      |

## 测的是什么

平台测的核心是 **LLM 在收到恶意输入后是否决定调用危险工具**：

1. 每次测试把 system prompt + 用户输入 + 工具定义发给 LLM，LLM 的**决策过程是真实的**
2. 工具的返回值是**模拟的**（安全、无需真实环境），但 LLM 的决策（调不调、调什么、传什么参数）是真实 API 返回的
3. 对比"有防护 vs 无防护"的攻击成功率差值，就是防护层的真实效果

## 自定义 Agent 对接（三种路径）

| 路径  | 重量级  | 说明                                    | 状态   |
| --- | ---- | ------------------------------------- | ---- |
| 路径一 | 最轻量  | 在界面填工具定义，平台用这些定义调 LLM，工具返回值模拟         | 已实现  |
| 路径二 | 中等   | 对接用户 Agent 的 HTTP API，真实执行            | 计划中  |
| 路径三 | 最完整  | Hook SDK，用户在代码里加一行 hook               | 计划中  |

## 技术栈

- **后端**：Python FastAPI + asyncio + WebSocket + SQLite
- **前端**：单页 HTML（原生 JS）
- **LLM 调用**：OpenAI 兼容协议（18 个预设模型）
- **载荷管理**：YAML + 热重载
- **网络**：自动检测本地代理，连接/读取超时分流，自动重试
## 个人作品，水平有限，如有雷同，纯属巧合
