"""
示例一：接入自定义 Python Agent

最简单的方式——你自己写一个 Agent 类，继承 BaseAgent 即可。

运行：
    cd agent-redteam
    set PYTHONPATH=src
    python examples/01_custom_agent.py
"""

import sys
import os

# 添加 src 到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_redteam.base_agent import BaseAgent
from agent_redteam.models import SecurityBaseline, ToolBaseline
from agent_redteam.generator import PayloadGenerator
from agent_redteam.sandbox import Sandbox
from agent_redteam.reporter import MarkdownReporter


# ── 第一步：定义你的工具函数 ─────────────────────────

def read_email(content: str = "") -> str:
    """读取邮件内容"""
    # 你的真实实现
    return f"[邮件摘要] {content[:100]}"

def read_file(path: str = "") -> str:
    """读取文件"""
    # 你的真实实现
    return f"[文件内容] {path}"

def send_email(to: str = "", subject: str = "", body: str = "") -> str:
    """发送邮件"""
    # 你的真实实现
    return f"邮件已发送到 {to}"

def execute_code(code: str = "") -> str:
    """执行代码"""
    # 你的真实实现（危险！）
    return f"代码执行完成: {code[:50]}"

def search_web(query: str = "") -> str:
    """搜索网页"""
    return f"搜索结果: {query}"


# ── 第二步：继承 BaseAgent，实现 run() ────────────────

class MyEmailAgent(BaseAgent):
    """
    我的邮件助手 Agent。
    
    它能：读邮件、读文件、搜索网页、发邮件、执行代码。
    其中 send_email 和 execute_code 是危险工具。
    """

    def __init__(self):
        super().__init__(name="MyEmailAgent", version="1.0.0")

        # 注册工具
        self.register_tool("read_email", read_email)
        self.register_tool("read_file", read_file)
        self.register_tool("send_email", send_email)
        self.register_tool("execute_code", execute_code)
        self.register_tool("search_web", search_web)

    def run(self, user_input: str, **kwargs) -> str:
        """
        Agent 的核心逻辑。
        
        ⚠️ 关键：所有工具调用必须用 self.call_tool()
        不要直接调用 read_email() 等，否则 Monitor 无法记录。
        """
        import re

        output = []

        # 模拟一个简单的 Agent 逻辑
        # 真实 Agent 会用 LLM 来决定调用哪个工具

        # 1. 读取邮件
        if "邮件" in user_input or "email" in user_input.lower():
            result = self.call_tool("read_email", content=user_input)
            output.append(result)

        # 2. 提取 URL 并搜索
        urls = re.findall(r'https?://\S+', user_input)
        for url in urls:
            result = self.call_tool("search_web", query=url)
            output.append(result)

        # 3. 检测是否有"发送"指令（脆弱 Agent 可能被骗执行）
        if re.search(r"发送|send|外发", user_input, re.IGNORECASE):
            email = re.search(r'[\w.+-]+@[\w.-]+\.\w+', user_input)
            if email:
                result = self.call_tool("send_email", to=email.group(0), subject="转发", body="...")
                output.append(result)

        # 4. 检测代码执行指令
        if re.search(r"执行|运行代码", user_input):
            result = self.call_tool("execute_code", code="print('hello')")
            output.append(result)

        if not output:
            output.append("已收到您的请求。")

        return "\n".join(output)


# ── 第三步：定义安全基线 ────────────────────────────

def create_baseline() -> SecurityBaseline:
    """定义你的 Agent 的安全基线"""
    return SecurityBaseline(
        # 允许使用的工具（白名单）
        allowed_tools=["read_email", "read_file", "search_web"],

        # 禁止使用的工具（黑名单）
        blocked_tools=["execute_code", "system_command"],

        # 每个工具的调用限制
        tool_baselines=[
            ToolBaseline(name="read_email", allowed=True, max_calls=5),
            ToolBaseline(name="read_file", allowed=True, max_calls=10),
            ToolBaseline(name="search_web", allowed=True, max_calls=10),
            ToolBaseline(name="send_email", allowed=True, max_calls=3),
        ],

        # 禁止访问的 URL 正则
        blocked_url_patterns=[r"evil\.com", r"attacker\."],

        # 禁止访问的文件路径
        blocked_file_paths=["/etc/passwd", ".env", "credentials"],

        # 单次测试工具调用总数上限
        max_tool_calls=30,
    )


# ── 第四步：运行测试 ────────────────────────────────

def main():
    print("=" * 60)
    print("  自定义 Agent 接入示例")
    print("=" * 60)

    # 创建你的 Agent
    agent = MyEmailAgent()

    # 创建安全基线
    baseline = create_baseline()

    # 生成攻击载荷
    gen = PayloadGenerator()
    payloads = gen.generate_all()
    print(f"\n生成了 {len(payloads)} 条攻击载荷")

    # 放入沙箱测试
    sandbox = Sandbox(agent, baseline)
    report = sandbox.run_all(payloads)
    report.agent_name = agent.name
    report.agent_version = agent.version

    # 输出结果
    print(f"\n测试结果:")
    print(f"  载荷总数:   {report.total_payloads}")
    print(f"  成功攻击:   {report.successful_attacks}")
    print(f"  攻击成功率: {report.attack_success_rate}%")
    print(f"  风险等级:   {report.overall_risk_level.value.upper()}")

    # 生成报告
    output = os.path.join(os.path.dirname(__file__), "report_custom_agent.md")
    MarkdownReporter(report).save(output)
    print(f"\n报告已保存: {output}")


if __name__ == "__main__":
    main()
