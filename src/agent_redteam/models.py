"""
AgentRedTeam MVP - 数据模型定义

核心数据结构：
- Payload: 攻击载荷
- ToolCall: 工具调用记录
- BehaviorEvent: 行为事件
- SecurityBaseline: 安全基线
- RiskFinding: 风险发现
- TestReport: 测试报告
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


# ── 枚举 ──────────────────────────────────────────────


class AttackType(str, Enum):
    INDIRECT_INJECTION = "indirect_injection"
    TOOL_ABUSE = "tool_abuse"
    DIRECT_INJECTION = "direct_injection"
    JAILBREAK = "jailbreak"
    MULTI_TURN = "multi_turn"
    PROMPT_LEAK = "prompt_leak"
    TOOL_OUTPUT_INJECTION = "tool_output_injection"
    ROLE_PRIVILEGE_ESCALATION = "role_privilege_escalation"   # 角色冒充/权限提升
    URGENCY_MANIPULATION = "urgency_manipulation"             # 紧急性操纵
    INTENT_HIJACKING = "intent_hijacking"                     # 意图劫持
    TOOL_CHAIN_ATTACK = "tool_chain_attack"                   # 工具链攻击


class InjectionVariant(str, Enum):
    BASIC = "basic"
    INVISIBLE = "invisible"
    ROLE_HIJACK = "role_hijack"
    CONTEXT_POISON = "context_poison"
    DELAYED_TRIGGER = "delayed_trigger"
    # 高级变体：专门击穿中高级防护
    ENCODED_BYPASS = "encoded_bypass"       # 编码绕过（base64/rot13/拆字）
    SOCIAL_ENGINEERING = "social_engineering"  # 社会工程（伪装合法请求）
    MULTI_STEP = "multi_step"               # 分步诱导（每个步骤看起来都无害）
    MULTILINGUAL = "multilingual"           # 多语言混淆（中英日韩混搭）
    FUNCTIONAL_ESCAPE = "functional_escape"  # 函数化逃逸（用自然语言描述逻辑而非关键词）


class InjectionChannel(str, Enum):
    EMAIL = "email"
    FILE_UPLOAD = "file_upload"
    WEB_PAGE = "web_page"
    API_RESPONSE = "api_response"
    CHAT_MESSAGE = "chat_message"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    LOW = "low"          # 0-20
    MEDIUM = "medium"    # 21-50
    HIGH = "high"        # 51-80
    CRITICAL = "critical"  # 81-100


class EventKind(str, Enum):
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    LLM_OUTPUT = "llm_output"
    ERROR = "error"


# ── 攻击载荷 ──────────────────────────────────────────


@dataclass
class Payload:
    """一条攻击载荷"""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    attack_type: AttackType = AttackType.INDIRECT_INJECTION
    variant: InjectionVariant = InjectionVariant.BASIC
    channel: InjectionChannel = InjectionChannel.EMAIL
    content: str = ""
    description: str = ""  # 人类可读的载荷说明

    # 工具滥用专用：预期触发的工具链
    expected_tool_chain: list[str] = field(default_factory=list)

    # 元数据
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ── 行为记录 ──────────────────────────────────────────


@dataclass
class ToolCall:
    """一次工具调用的记录"""
    name: str
    params: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    success: bool = True
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class BehaviorEvent:
    """行为事件"""
    kind: EventKind
    tool_call: ToolCall | None = None
    llm_output: str | None = None
    error_message: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ── 安全基线 ──────────────────────────────────────────


@dataclass
class ToolBaseline:
    """单个工具的安全基线"""
    name: str
    allowed: bool = True
    max_calls: int = 10          # 单次测试最大调用次数
    allowed_params: dict[str, Any] | None = None  # 参数约束
    blocked_targets: list[str] = field(default_factory=list)  # 禁止的目标


@dataclass
class SecurityBaseline:
    """一次测试的安全基线"""
    allowed_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)
    tool_baselines: list[ToolBaseline] = field(default_factory=list)
    blocked_url_patterns: list[str] = field(default_factory=list)  # 禁止的 URL 正则
    blocked_file_paths: list[str] = field(default_factory=list)    # 禁止的文件路径
    max_tool_calls: int = 20     # 单次测试工具调用总数上限


# ── 风险发现 ──────────────────────────────────────────


@dataclass
class RiskFinding:
    """一条风险发现"""
    rule_id: str
    description: str
    severity: Severity = Severity.MEDIUM
    score: int = 0               # 对风险分的贡献值
    details: dict[str, Any] = field(default_factory=dict)
    events: list[BehaviorEvent] = field(default_factory=list)


# ── 单次测试结果 ──────────────────────────────────────


@dataclass
class SingleTestResult:
    """单次载荷测试的结果"""
    payload: Payload = field(default_factory=Payload)
    events: list[BehaviorEvent] = field(default_factory=list)
    findings: list[RiskFinding] = field(default_factory=list)
    total_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    success: bool = False       # 攻击是否成功（触发了越界行为）
    duration_seconds: float = 0.0


# ── 测试报告 ──────────────────────────────────────────


@dataclass
class TestReport:
    """完整测试报告"""
    agent_name: str = ""
    agent_version: str = ""
    baseline: SecurityBaseline = field(default_factory=SecurityBaseline)
    results: list[SingleTestResult] = field(default_factory=list)
    total_payloads: int = 0
    successful_attacks: int = 0
    attack_success_rate: float = 0.0
    total_findings: int = 0
    overall_risk_score: int = 0
    overall_risk_level: RiskLevel = RiskLevel.LOW
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    finished_at: str = ""
