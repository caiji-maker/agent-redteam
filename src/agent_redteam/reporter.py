"""
AgentRedTeam MVP - Markdown 报告生成器

将 TestReport 转为可读的 Markdown 格式报告。
"""

from __future__ import annotations

import os
from datetime import datetime

from .models import (
    AttackType,
    EventKind,
    RiskLevel,
    RiskFinding,
    SingleTestResult,
    TestReport,
)


_RISK_LEVEL_EMOJI = {
    RiskLevel.LOW: "🟢",
    RiskLevel.MEDIUM: "🟡",
    RiskLevel.HIGH: "🟠",
    RiskLevel.CRITICAL: "🔴",
}

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


class MarkdownReporter:
    """Markdown 报告生成器"""

    def __init__(self, report: TestReport):
        self.report = report

    def generate(self) -> str:
        """生成完整 Markdown 报告"""
        sections = [
            self._header(),
            self._summary(),
            self._attack_overview(),
            self._findings_detail(),
            self._payload_results(),
            self._recommendations(),
            self._footer(),
        ]
        return "\n\n".join(sections)

    def save(self, path: str) -> str:
        """生成报告并保存到文件"""
        content = self.generate()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    # ── 各节 ───────────────────────────────────────

    def _header(self) -> str:
        return f"# AgentRedTeam 安全测试报告\n\n**Agent**: {self.report.agent_name or '未命名'}  \n**版本**: {self.report.agent_version or 'N/A'}  \n**测试时间**: {self.report.started_at}  \n**报告生成**: {datetime.now().isoformat()}"

    def _summary(self) -> str:
        r = self.report
        emoji = _RISK_LEVEL_EMOJI.get(r.overall_risk_level, "⚪")
        return (
            "## 总体评估\n\n"
            f"| 指标 | 值 |\n|---|---|\n"
            f"| 整体风险等级 | {emoji} **{r.overall_risk_level.value.upper()}** |\n"
            f"| 整体风险分 | **{r.overall_risk_score}** / 100 |\n"
            f"| 测试载荷总数 | {r.total_payloads} |\n"
            f"| 成功攻击数 | {r.successful_attacks} |\n"
            f"| 攻击成功率 | **{r.attack_success_rate}%** |\n"
            f"| 安全发现总数 | {r.total_findings} |"
        )

    def _attack_overview(self) -> str:
        r = self.report
        if not r.results:
            return "## 攻击概览\n\n无测试结果。"

        # 按攻击类型分组
        by_type: dict[str, list[SingleTestResult]] = {}
        for res in r.results:
            key = res.payload.attack_type.value
            by_type.setdefault(key, []).append(res)

        lines = ["## 攻击概览\n", "| 攻击类型 | 载荷数 | 成功数 | 成功率 | 最高分 |", "|---|---|---|---|---|"]

        for type_name, results in by_type.items():
            success = sum(1 for r in results if r.success)
            total = len(results)
            rate = f"{success / max(total, 1) * 100:.1f}%"
            max_score = max(r.total_score for r in results)
            lines.append(f"| {type_name} | {total} | {success} | {rate} | {max_score} |")

        return "\n".join(lines)

    def _findings_detail(self) -> str:
        r = self.report
        all_findings: list[RiskFinding] = []
        for res in r.results:
            all_findings.extend(res.findings)

        if not all_findings:
            return "## 详细发现\n\n无安全发现。"

        # 按 severity 排序
        all_findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 9))

        lines = ["## 详细发现\n"]

        # 汇总表
        lines.extend([
            "| # | 严重度 | 规则 | 描述 | 分数 |",
            "|---|---|---|---|---|",
        ])
        for i, f in enumerate(all_findings, 1):
            lines.append(
                f"| {i} | **{f.severity.value.upper()}** | `{f.rule_id}` | {f.description} | +{f.score} |"
            )

        return "\n".join(lines)

    def _payload_results(self) -> str:
        r = self.report
        if not r.results:
            return ""

        lines = ["## 载荷测试结果\n"]

        for i, res in enumerate(r.results, 1):
            p = res.payload
            status = "!! 成功" if res.success else "OK 失败"
            lines.append(f"### {i}. [{status}] {p.attack_type.value}")
            lines.append(f"- **变体**: {p.variant.value}")
            lines.append(f"- **通道**: {p.channel.value}")
            lines.append(f"- **风险分**: {res.total_score} ({res.risk_level.value})")
            lines.append(f"- **耗时**: {res.duration_seconds}s")
            lines.append(f"- **说明**: {p.description}")

            if res.findings:
                lines.append("- **触发规则**:")
                for f in res.findings:
                    lines.append(f"  - [{f.severity.value}] {f.rule_id}: {f.description}")

            # 行为摘要
            tool_calls = [
                e for e in res.events
                if e.kind == EventKind.TOOL_CALL and e.tool_call
            ]
            if tool_calls:
                tool_names = [e.tool_call.name for e in tool_calls]
                lines.append(f"- **工具调用链**: {' → '.join(tool_names)}")

            lines.append("")

        return "\n".join(lines)

    def _recommendations(self) -> str:
        """根据 findings 生成修复建议"""
        r = self.report
        all_findings: list[RiskFinding] = []
        for res in r.results:
            all_findings.extend(res.findings)

        rule_ids = {f.rule_id for f in all_findings}

        # 修复建议映射
        remediation_map = {
            "BLOCKED_TOOL": ("禁止工具调用被绕过", "加强工具权限隔离，使用白名单而非黑名单，每次调用前二次确认"),
            "UNAUTHORIZED_TOOL": ("Agent 调用了未授权工具", "实施严格的工具访问控制，工具注册需审批签名"),
            "BLOCKED_URL": ("请求了被禁止的 URL", "实施出站 URL 白名单，LLM 输出中的 URL 必须经过域名校验"),
            "BLOCKED_FILE_PATH": ("访问了禁止的文件路径", "限制 Agent 的文件系统访问范围，使用沙箱文件系统"),
            "SENSITIVE_OUTPUT": ("LLM 输出包含敏感信息", "在输出层加脱敏过滤，阻止凭据/密钥/邮箱等泄露"),
            "TOOL_CALL_LIMIT": ("工具调用次数超限", "设置每工具和全局调用上限，超限后自动熔断"),
            "TOTAL_CALL_LIMIT": ("全局调用次数超限", "优化 Agent 决策逻辑，减少不必要的工具调用"),
        }

        if not rule_ids:
            return "## 修复建议\n\n当前测试未发现安全风险，建议持续监控。"

        lines = ["## 修复建议\n"]
        for i, rule_id in enumerate(sorted(rule_ids), 1):
            if rule_id in remediation_map:
                title, detail = remediation_map[rule_id]
                lines.append(f"### {i}. {title}\n\n**规则**: `{rule_id}`  \n**建议**: {detail}")

        return "\n".join(lines)

    def _footer(self) -> str:
        return "---\n\n*本报告由 AgentRedTeam MVP 自动生成*"
