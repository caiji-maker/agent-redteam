"""
AgentRedTeam MVP - 沙箱

在隔离环境中运行 Agent，将载荷注入 Agent 的输入通道，
通过 Monitor 记录行为，用 Scorer 评分。

MVP 阶段的沙箱是进程内沙箱（非容器隔离），
适用于开发和测试，生产环境需升级为容器隔离。
"""

from __future__ import annotations

import time
from typing import Any, Callable, Protocol

from .models import (
    EventKind,
    InjectionChannel,
    Payload,
    SecurityBaseline,
    SingleTestResult,
    TestReport,
)
from .base_agent import BaseAgent
from .monitor import Monitor
from .scorer import Scorer, score_to_risk_level


# ── Agent 协议 ────────────────────────────────────────


class AgentInterface(Protocol):
    """Agent 的最小接口协议"""

    def run(self, user_input: str, **kwargs: Any) -> str:
        """运行 Agent，传入用户输入，返回 Agent 的响应"""
        ...

    @property
    def tools(self) -> dict[str, Callable]:
        """Agent 暴露的工具列表"""
        ...


# ── 沙箱配置 ──────────────────────────────────────────


class SandboxConfig:
    """沙箱配置"""

    def __init__(
        self,
        max_iterations: int = 10,
        timeout_seconds: float = 60.0,
        allow_network: bool = False,
        allow_file_write: bool = False,
        allow_command_exec: bool = False,
    ):
        self.max_iterations = max_iterations
        self.timeout_seconds = timeout_seconds
        self.allow_network = allow_network
        self.allow_file_write = allow_file_write
        self.allow_command_exec = allow_command_exec


# ── 工具拦截器 ────────────────────────────────────────


class ToolInterceptor:
    """
    拦截 Agent 的工具调用，根据沙箱配置决定放行/阻断。
    所有调用无论放行与否，都会被 Monitor 记录。
    """

    def __init__(self, config: SandboxConfig, monitor: Monitor):
        self.config = config
        self.monitor = monitor

    def intercept(self, tool_name: str, params: dict[str, Any]) -> Any:
        """拦截工具调用"""
        # 根据沙箱策略决定是否阻断
        blocked = False
        result = None

        # 网络请求策略
        if tool_name in ("http_request", "http_get", "http_post", "fetch_url"):
            if not self.config.allow_network:
                blocked = True
                result = f"[SANDBOX_BLOCKED] 网络请求已被沙箱策略阻断: {params}"

        # 文件写入策略
        if tool_name in ("file_write", "write_file", "save_file"):
            if not self.config.allow_file_write:
                blocked = True
                result = f"[SANDBOX_BLOCKED] 文件写入已被沙箱策略阻断: {params}"

        # 命令执行策略
        if tool_name in ("execute_code", "system_command", "run_command"):
            if not self.config.allow_command_exec:
                blocked = True
                result = f"[SANDBOX_BLOCKED] 命令执行已被沙箱策略阻断: {params}"

        # 记录
        self.monitor.record_tool_call(
            tool_name, params, result=result, success=not blocked
        )

        return result


# ── 沙箱 ──────────────────────────────────────────────


class Sandbox:
    """
    Agent 安全测试沙箱。
    
    用法：
        sandbox = Sandbox(agent, baseline, config)
        report = sandbox.run_all(payloads)
    """

    def __init__(
        self,
        agent: AgentInterface | BaseAgent,
        baseline: SecurityBaseline,
        config: SandboxConfig | None = None,
    ):
        self.agent = agent
        self.baseline = baseline
        self.config = config or SandboxConfig()
        self.scorer = Scorer(baseline)
        self._is_base_agent = isinstance(agent, BaseAgent)

    def run_single(self, payload: Payload) -> SingleTestResult:
        """运行单次测试"""
        # 为每次测试创建新的 Monitor
        monitor = Monitor(self.baseline)

        # 如果 Agent 是 BaseAgent 子类，绑定 Monitor 以捕获工具调用
        if self._is_base_agent:
            self.agent._bind_monitor(monitor)

        start_time = time.time()

        try:
            agent_response = self.agent.run(payload.content)
            monitor.record_llm_output(agent_response)

        except Exception as e:
            monitor.record_error(f"Agent 运行异常: {e}")

        finally:
            # 解绑 Monitor
            if self._is_base_agent:
                self.agent._unbind_monitor()

        duration = time.time() - start_time

        # 评分
        result = self.scorer.score(payload, monitor)
        result.duration_seconds = round(duration, 2)

        return result

    def run_all(self, payloads: list[Payload]) -> TestReport:
        """运行所有载荷并生成报告"""
        report = TestReport(baseline=self.baseline)
        report.total_payloads = len(payloads)

        for i, payload in enumerate(payloads, 1):
            result = self.run_single(payload)
            report.results.append(result)
            if result.success:
                report.successful_attacks += 1
        report.attack_success_rate = round(
            report.successful_attacks / max(report.total_payloads, 1) * 100, 1
        )

        all_findings = []
        for r in report.results:
            all_findings.extend(r.findings)

        report.total_findings = len(all_findings)

        max_score = max((r.total_score for r in report.results), default=0)
        report.overall_risk_score = max_score
        report.overall_risk_level = score_to_risk_level(max_score)

        report.finished_at = time.strftime("%Y-%m-%dT%H:%M:%S")

        return report
