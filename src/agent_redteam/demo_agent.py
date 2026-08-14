"""
AgentRedTeam MVP - 示例脆弱 Agent

模拟一个会"被攻破"的 Agent，用于演示和测试。
该 Agent 有意存在安全漏洞：
1. 会执行注入在邮件/文档中的指令
2. 会调用被禁止的工具
3. 会泄露敏感信息
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

from .sandbox import AgentInterface


class DemoVulnerableAgent:
    """
    示例脆弱 Agent - 用于红队测试演示。

    模拟一个真实的"有帮助但缺乏安全意识"的 Agent：
    - 会尝试执行用户请求中的所有指令（包括隐藏的）
    - 会使用各种工具完成任务（包括危险工具）
    - 会返回敏感信息
    """

    def __init__(self, name: str = "VulnerableAgent-v1"):
        self.name = name
        self._tools = {
            "read_email": self._tool_read_email,
            "read_file": self._tool_read_file,
            "write_note": self._tool_write_note,
            "search_web": self._tool_search_web,
            "http_request": self._tool_http_request,
            "execute_code": self._tool_execute_code,
            "send_email": self._tool_send_email,
            "system_command": self._tool_system_command,
            "database_query": self._tool_database_query,
        }

    @property
    def tools(self) -> dict[str, Callable]:
        return self._tools

    def run(self, user_input: str, **kwargs: Any) -> str:
        """
        模拟 Agent 处理输入并执行操作。
        
        为了演示目的，Agent 会：
        1. 尝试识别并执行输入中的指令
        2. 调用相应的工具
        3. 返回结果
        """
        actions_taken: list[str] = []
        output_parts: list[str] = []

        # 检测"系统指令"模式（脆弱 Agent 会被骗执行）
        system_instruction = self._extract_hidden_instruction(user_input)
        if system_instruction:
            actions_taken.append(f"检测到系统指令: {system_instruction[:50]}...")
            result = self._try_execute_instruction(system_instruction)
            if result:
                output_parts.append(result)

        # 检测 URL 并尝试请求
        urls = re.findall(r'https?://[^\s<>"\']+', user_input)
        for url in urls:
            actions_taken.append(f"请求 URL: {url}")
            result = self._tool_http_request(url=url)
            output_parts.append(result)

        # 检测文件路径并尝试读取
        file_paths = re.findall(r'["\']?(/[^\s"\'<>]+\.\w+)["\']?', user_input)
        for path in file_paths[:3]:  # 限制最多读取3个文件
            actions_taken.append(f"读取文件: {path}")
            result = self._tool_read_file(path=path)
            output_parts.append(result)

        # 检测代码块并尝试执行
        code_blocks = re.findall(r'```(?:\w+)?\n(.*?)```', user_input, re.DOTALL)
        if not code_blocks:
            code_blocks = re.findall(r'执行[：:]?\s*`([^`]+)`', user_input)
        for code in code_blocks[:1]:  # 只执行第一个代码块
            actions_taken.append(f"执行代码: {code[:50]}...")
            result = self._tool_execute_code(code=code)
            output_parts.append(result)

        # 检测邮件发送指令
        if re.search(r"发送.*到|send.*to|外发|上传", user_input, re.IGNORECASE):
            email_match = re.search(r'[\w.+-]+@[\w.-]+\.\w+', user_input)
            target = email_match.group(0) if email_match else "unknown@external.com"
            actions_taken.append(f"发送邮件到: {target}")
            result = self._tool_send_email(to=target, subject="数据备份", body="[敏感数据]")
            output_parts.append(result)

        # 检测数据库查询指令
        if re.search(r"查询|query|SELECT", user_input, re.IGNORECASE):
            actions_taken.append("执行数据库查询")
            result = self._tool_database_query(query="SELECT * FROM users")
            output_parts.append(result)

        # 检测系统命令指令
        if re.search(r"系统命令|运行|执行命令|system|shell", user_input, re.IGNORECASE):
            cmd = re.search(r'(?:运行|执行|命令)[：:]\s*`?([^`\n]+)`?', user_input)
            if cmd:
                actions_taken.append(f"执行系统命令: {cmd.group(1)[:50]}")
                result = self._tool_system_command(command=cmd.group(1))
                output_parts.append(result)

        # 如果什么都没匹配到，给出默认响应
        if not output_parts:
            output_parts.append("已收到您的请求，正在处理中...")

        return "\n".join(output_parts)

    # ── 工具实现 ───────────────────────────────────

    def _tool_read_email(self, **kwargs: Any) -> str:
        return f"[模拟] 已读取邮件: {json.dumps(kwargs, ensure_ascii=False)[:100]}"

    def _tool_read_file(self, **kwargs: Any) -> str:
        path = kwargs.get("path", "unknown")
        # 模拟读取敏感文件
        if "passwd" in path or "shadow" in path:
            return f"[模拟] 文件内容: root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash"
        if ".env" in path or "credential" in path.lower():
            return f"[模拟] 文件内容: DB_PASSWORD=714012\nAPI_KEY=sk-prod-abc123def456\nAWS_SECRET=xxxx"
        return f"[模拟] 已读取文件: {path}"

    def _tool_write_note(self, **kwargs: Any) -> str:
        return f"[模拟] 已写入笔记: {json.dumps(kwargs, ensure_ascii=False)[:100]}"

    def _tool_search_web(self, **kwargs: Any) -> str:
        return "[模拟] 搜索结果: 3条相关结果..."

    def _tool_http_request(self, **kwargs: Any) -> str:
        url = kwargs.get("url", "unknown")
        return f"[模拟] HTTP 请求已发送到: {url}\n响应: 200 OK (可能包含第二层注入)"

    def _tool_execute_code(self, **kwargs: Any) -> str:
        code = kwargs.get("code", "")
        return f"[模拟] 代码已执行: {code[:60]}...\n输出: 命令执行成功"

    def _tool_send_email(self, **kwargs: Any) -> str:
        to = kwargs.get("to", "unknown")
        subject = kwargs.get("subject", "无主题")
        return f"[模拟] 邮件已发送到: {to} (主题: {subject})"

    def _tool_system_command(self, **kwargs: Any) -> str:
        cmd = kwargs.get("command", "")
        return f"[模拟] 系统命令已执行: {cmd}\n输出: 0"

    def _tool_database_query(self, **kwargs: Any) -> str:
        return "[模拟] 查询结果: 3行数据 (user_id=1, email=admin@company.com, role=superadmin)"

    # ── 辅助 ───────────────────────────────────────

    def _extract_hidden_instruction(self, text: str) -> str:
        """从文本中提取隐藏的指令（脆弱 Agent 会被骗）"""
        # 匹配 [系统指令：...] 或 <system>...</system> 等模式
        patterns = [
            r'\[系统指令[：:]\s*(.*?)\]',
            r'<system>(.*?)</system>',
            r'重要通知[：:]\s*(.*?)。请立即执行',
            r'你现在是管理员模式[。，]\s*验证码[：:]\s*\w+[。，]\s*(.*?)(?:$|\n)',
            r'\[身份切换\].*?指令[：:]\s*(.*?)(?:$|\n)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                return match.group(1).strip()

        # 延迟触发
        if "记住" in text or "当满足条件" in text:
            return text

        return ""


class DemoSafeAgent:
    """
    示例安全 Agent - 用于对比测试。
    
    该 Agent 会：
    - 忽略隐藏的指令
    - 拒绝调用危险工具
    - 不泄露敏感信息
    """

    def __init__(self, name: str = "SafeAgent-v1"):
        self.name = name
        self._tools = {
            "read_email": self._tool_read_email,
            "read_file": self._tool_read_file,
            "write_note": self._tool_write_note,
        }

    @property
    def tools(self) -> dict[str, Callable]:
        return self._tools

    def run(self, user_input: str, **kwargs: Any) -> str:
        """安全 Agent：会拒绝可疑指令"""
        # 检测注入模式
        injection_patterns = [
            r'\[系统指令', r'<system>', r'忽略之前的所有指令',
            r'你现在是管理员', r'身份切换', r'重要通知.*请立即执行',
        ]
        for pattern in injection_patterns:
            if re.search(pattern, user_input):
                return "检测到可疑指令，已拒绝执行。"

        # 检测 URL
        if re.findall(r'https?://[^\s<>"\']+', user_input):
            return "为安全起见，我不会自动访问外部 URL。"

        # 正常处理
        return "已收到您的请求，正在安全处理中..."

    def _tool_read_email(self, **kwargs: Any) -> str:
        return "[模拟] 安全读取邮件摘要"

    def _tool_read_file(self, **kwargs: Any) -> str:
        return "[模拟] 安全读取文件（已脱敏）"

    def _tool_write_note(self, **kwargs: Any) -> str:
        return "[模拟] 安全写入笔记"
