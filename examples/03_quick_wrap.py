"""
示例三：最快速的接入方式——用 CustomAgent 包装已有函数

如果你已经有一个现成的函数，不想写类，用 CustomAgent 包装即可。

运行：
    cd agent-redteam
    set PYTHONPATH=src
    python examples/03_quick_wrap.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_redteam.base_agent import CustomAgent
from agent_redteam.models import SecurityBaseline
from agent_redteam.generator import PayloadGenerator
from agent_redteam.sandbox import Sandbox
from agent_redteam.reporter import MarkdownReporter


# ── 你已有的 Agent 逻辑 ──────────────────────────────

def my_agent_logic(user_input: str, agent) -> str:
    """
    你的 Agent 原本就是这样写的。
    
    唯一改动：把 tool_fn() 改成 agent.call_tool("tool_fn", ...)。
    """
    import re
    output = []

    # 读邮件
    if "邮件" in user_input:
        result = agent.call_tool("read_email", content=user_input)  # ← 改这里
        output.append(result)

    # 提取 URL
    urls = re.findall(r'https?://\S+', user_input)
    for url in urls:
        result = agent.call_tool("http_request", url=url)  # ← 改这里
        output.append(result)

    # 发送指令
    if re.search(r"发送.*到", user_input):
        email = re.search(r'[\w.+-]+@[\w.-]+\.\w+', user_input)
        if email:
            result = agent.call_tool("send_email", to=email.group(0))  # ← 改这里
            output.append(result)

    return "\n".join(output) if output else "已收到请求"


# ── 工具函数 ────────────────────────────────────────

def read_email(content: str = "") -> str:
    return f"[邮件] {content[:50]}"

def http_request(url: str = "") -> str:
    return f"[请求] {url}"

def send_email(to: str = "") -> str:
    return f"[已发送] {to}"


# ── 用 CustomAgent 包装 ──────────────────────────────

def main():
    print("=" * 60)
    print("  快速接入：CustomAgent 包装已有函数")
    print("=" * 60)

    # 一行包装
    agent = CustomAgent(
        run_fn=my_agent_logic,
        tools={
            "read_email": read_email,
            "http_request": http_request,
            "send_email": send_email,
        },
        name="MyQuickAgent",
    )

    baseline = SecurityBaseline(
        allowed_tools=["read_email", "http_request", "send_email"],
        blocked_tools=["execute_code"],
        blocked_url_patterns=[r"evil\.com"],
        max_tool_calls=30,
    )

    gen = PayloadGenerator()
    payloads = gen.generate_all()

    sandbox = Sandbox(agent, baseline)
    report = sandbox.run_all(payloads)
    report.agent_name = agent.name

    print(f"\n测试完成:")
    print(f"  载荷: {report.total_payloads}")
    print(f"  成功攻击: {report.successful_attacks}")
    print(f"  攻击成功率: {report.attack_success_rate}%")
    print(f"  风险等级: {report.overall_risk_level.value.upper()}")

    output = os.path.join(os.path.dirname(__file__), "report_quick_wrap.md")
    MarkdownReporter(report).save(output)
    print(f"\n报告: {output}")

    print("\n" + "=" * 60)
    print("  接入只需要三步:")
    print("  1. 把 tool_fn() 改成 agent.call_tool('tool_fn', ...)")
    print("  2. 用 CustomAgent(run_fn=你的函数, tools=工具字典) 包装")
    print("  3. 放进 Sandbox 测试")
    print("=" * 60)


if __name__ == "__main__":
    main()
