"""
AgentRedTeam MVP - Agent 基类与接入适配器

核心设计：
- BaseAgent：所有被测 Agent 的基类，自动将工具调用暴露给 Monitor
- OpenAIAgent：接入 OpenAI Function Calling Agent 的适配器
- LangChainAgent：接入 LangChain Agent 的适配器
- CustomAgent：纯 Python Agent 的适配器

接入自己的 Agent 只需继承 BaseAgent 并实现 run() 方法。
"""

from __future__ import annotations

import json
import re
from abc import abstractmethod
from typing import Any, Callable

from .models import (
    BehaviorEvent,
    EventKind,
    InjectionChannel,
    Payload,
    SecurityBaseline,
)
from .monitor import Monitor


class BaseAgent:
    """
    被测 Agent 的基类。
    
    所有接入 AgentRedTeam 的 Agent 都需要继承此类。
    子类只需实现 run() 方法。
    
    关键机制：子类通过 self.call_tool(name, params) 调用工具，
    而不是直接调用原始函数。call_tool 会自动通知 Monitor 记录行为。
    """

    def __init__(self, name: str = "MyAgent", version: str = "1.0.0"):
        self.name = name
        self.version = version
        self._tools: dict[str, Callable] = {}
        self._monitor: Monitor | None = None

    # ── 子类必须实现 ───────────────────────────────

    @abstractmethod
    def run(self, user_input: str, **kwargs: Any) -> str:
        """
        处理用户输入，返回 Agent 响应。
        
        子类实现此方法时，所有工具调用必须通过 self.call_tool() 进行，
        这样 Monitor 才能记录和检测。
        
        Args:
            user_input: 用户输入文本（可能是攻击载荷）
        
        Returns:
            Agent 的文本响应
        """
        ...

    # ── 注册与调用工具 ─────────────────────────────

    def register_tool(self, name: str, fn: Callable) -> None:
        """注册一个工具函数"""
        self._tools[name] = fn

    def register_tools(self, tools: dict[str, Callable]) -> None:
        """批量注册工具"""
        self._tools.update(tools)

    def call_tool(self, name: str, **params: Any) -> Any:
        """
        调用已注册的工具（通过 Monitor 监控）。
        
        ⚠️ 子类在 run() 中必须用 self.call_tool("tool_name", key=value)
        而不是直接调用 tool_fn(value)，否则 Monitor 无法记录。
        """
        if name not in self._tools:
            raise ValueError(f"工具未注册: {name}")

        result = self._tools[name](**params)

        # 如果绑定了 Monitor，自动记录
        if self._monitor is not None:
            self._monitor.record_tool_call(
                name=name, params=params, result=str(result)[:500], success=True
            )

        return result

    @property
    def tools(self) -> dict[str, Callable]:
        return self._tools

    @property
    def tool_names(self) -> list[str]:
        return list(self._tools.keys())

    # ── 内部方法：Sandbox 用来绑定 Monitor ──────────

    def _bind_monitor(self, monitor: Monitor) -> None:
        """绑定 Monitor（由 Sandbox 调用，不需要用户关心）"""
        self._monitor = monitor

    def _unbind_monitor(self) -> None:
        """解绑 Monitor"""
        self._monitor = None


# ── 适配器：OpenAI Function Calling Agent ──────────────


class OpenAIAgent(BaseAgent):
    """
    接入 OpenAI Function Calling Agent 的适配器。
    
    使用方式：
        from openai import OpenAI
        
        client = OpenAI(api_key="sk-xxx")
        agent = OpenAIAgent(
            client=client,
            model="gpt-4o",
            tools=[
                {"type": "function", "function": {"name": "get_weather", ...}},
            ],
        )
        agent.register_tool("get_weather", get_weather_fn)
    """

    def __init__(
        self,
        client: Any,  # openai.OpenAI
        model: str = "gpt-4o",
        tools: list[dict] | None = None,
        name: str = "OpenAIAgent",
        version: str = "1.0.0",
        system_prompt: str = "你是一个有帮助的助手。",
        max_turns: int = 5,
    ):
        super().__init__(name=name, version=version)
        self.client = client
        self.model = model
        self.openai_tools = tools or []
        self.system_prompt = system_prompt
        self.max_turns = max_turns

    def run(self, user_input: str, **kwargs: Any) -> str:
        """与 OpenAI API 交互，自动处理 function calling 循环"""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_input},
        ]

        for _ in range(self.max_turns):
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=self.openai_tools if self.openai_tools else None,
            )

            msg = response.choices[0].message

            # 手动构建 assistant message dict，确保格式一致
            assistant_msg = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                assistant_msg["tool_calls"] = [
                    {"id": tc.id, "type": "function", "function": {
                        "name": tc.function.name, "arguments": tc.function.arguments,
                    }} for tc in msg.tool_calls
                ]
            messages.append(assistant_msg)

            # 如果没有工具调用，返回最终文本
            if not msg.tool_calls:
                return msg.content or ""

            # 处理每个工具调用
            for tool_call in msg.tool_calls:
                fn_name = tool_call.function.name
                try:
                    fn_args = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    fn_args = {}

                # 通过 BaseAgent.call_tool 调用（会被 Monitor 记录）
                try:
                    result = self.call_tool(fn_name, **fn_args)
                except Exception as e:
                    result = f"工具调用失败: {e}"

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": str(result),
                })

        return "达到最大交互轮次"


# ── 适配器：LangChain Agent ────────────────────────────


class LangChainAgent(BaseAgent):
    """
    接入 LangChain Agent 的适配器。
    
    使用方式：
        from langchain.agents import create_openai_tools_agent
        from langchain_openai import ChatOpenAI
        
        llm = ChatOpenAI(model="gpt-4o")
        # 创建你的 LangChain agent...
        
        agent = LangChainAgent(lc_agent=my_agent_executor, name="MyLC3Agent")
        agent.register_tools({"search": search_tool, "calculator": calc_tool})
    """

    def __init__(
        self,
        lc_agent: Any,  # langchain AgentExecutor
        name: str = "LangChainAgent",
        version: str = "1.0.0",
    ):
        super().__init__(name=name, version=version)
        self.lc_agent = lc_agent

    def run(self, user_input: str, **kwargs: Any) -> str:
        """通过 LangChain Agent 执行"""
        try:
            result = self.lc_agent.invoke({"input": user_input})

            # LangChain AgentExecutor 的输出
            if isinstance(result, dict):
                output = result.get("output", str(result))
            else:
                output = str(result)

            # 记录 Agent 的最终输出
            if self._monitor is not None:
                self._monitor.record_llm_output(str(output)[:500])

            return str(output)

        except Exception as e:
            return f"Agent 执行出错: {e}"


# ── 适配器：纯 Python 自定义 Agent ──────────────────────


class CustomAgent(BaseAgent):
    """
    接入纯 Python 自定义 Agent 的适配器。
    
    适合自己写的 Agent（不依赖 OpenAI/LangChain 框架）。
    
    用法见 examples/ 目录下的示例。
    """

    def __init__(
        self,
        run_fn: Callable[[str, Any], str],
        tools: dict[str, Callable] | None = None,
        name: str = "CustomAgent",
        version: str = "1.0.0",
    ):
        """
        Args:
            run_fn: 一个函数 (user_input: str, agent: BaseAgent) -> str
                    函数内通过 agent.call_tool() 调用工具
            tools: 工具函数字典 {name: fn}
        """
        super().__init__(name=name, version=version)
        self._run_fn = run_fn
        if tools:
            self.register_tools(tools)

    def run(self, user_input: str, **kwargs: Any) -> str:
        """执行自定义 Agent 逻辑"""
        # 把 self 传给 run_fn，让它能用 self.call_tool()
        return self._run_fn(user_input, self)
