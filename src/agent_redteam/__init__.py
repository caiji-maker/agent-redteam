"""
AgentRedTeam - 基于Agent普及的网络安全攻防平台

用法:
    agent-redteam run --agent demo --output report.md
    agent-redteam scan --agent my_agent
    agent-redteam generate --type indirect_injection --count 5
"""

from .models import *
from .generator import PayloadGenerator
from .monitor import Monitor
from .scorer import Scorer, score_to_risk_level
from .sandbox import Sandbox, SandboxConfig
from .reporter import MarkdownReporter

__version__ = "0.3.0"
