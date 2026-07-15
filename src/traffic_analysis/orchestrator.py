import json
from dataclasses import dataclass, field
from typing import Any, Optional

from openai import AsyncOpenAI

from .llm_config import Config
from .logger import get_logger

logger = get_logger(__name__)

DISPATCH_PROMPT = (
    "你是网络安全调度员。分析下面的网络会话数据，决定应该调用哪些专家小模型来分析。\n\n"
    "| 专家名称 | 擅长 | 何时调用 |\n"
    "|----------|------|----------|\n"
    "| ThreatIntelExpert | IP/域名威胁情报 | 有外部IP通信时 |\n"
    "| BeaconDetectorExpert | C2 Beacon 时序检测 | 通信有规律性、固定间隔 |\n"
    "| DNSTunnelExpert | DNS 隧道/外泄 | DNS 查询异常大或频繁 |\n"
    "| PortScanExpert | 端口扫描 | 短时间内大量SYN到不同端口 |\n"
    "| ICMPTunnelExpert | ICMP 隐蔽信道 | ICMP 载荷异常大(>100B) |\n"
    "| PayloadExpert | 载荷/外泄分析 | 大量上传、固定载荷 |\n\n"
    "- 精准选择 1-3 个相关专家\n"
    "- 不要调用不相关的专家\n"
    "- 如果明显是攻击设置 alert=true\n\n"
    "{\n"
    '  "reasoning": "为什么选择这些专家的推理过程",\n'
    '  "experts_to_call": ["Expert1", "Expert2"],\n'
    '  "alert": true/false\n'
    "}"
)

SYNTHESIS_PROMPT = (
    "你是资深网络安全分析师。请综合以下专家小模型的检测结果，给出最终安全分析报告。\n\n"
    "{expert_results}\n\n"
    "{session_summary}\n\n"
    "{{\n"
    '  "is_malicious": true/false,\n'
    '  "attack_type": "具体攻击类型或Normal",\n'
    '  "threat_level": "Critical/High/Medium/Low/None",\n'
    '  "confidence": 0.0-1.0,\n'
    '  "attck_techniques": ["Txxxx"],\n'
    '  "iocs": {{"ips": [], "domains": []}},\n'
    '  "recommendations": ["具体建议"]\n'
    "}}"
)

SESSION_FORMAT_MAX_CHARS = 3000
SESSION_SYNTH_MAX_CHARS = 2000
PROMPT_MAX_CHARS = 4000
PACKET_SAMPLE_COUNT = 15


@dataclass
class FinalReport:
    session_id: str = ""
    is_malicious: bool = False
    attack_type: str = "Normal"
    threat_level: str = "None"
    confidence: float = 0.0
    attck_techniques: list[str] = field(default_factory=list)
    expert_findings: dict[str, Any] = field(default_factory=dict)
    dispatch_reasoning: str = ""
    iocs: dict[str, list[str]] = field(default_factory=dict)
    timeline: str = ""
    recommendations: list[str] = field(default_factory=list)


class LLMOrchestrator:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._init_backend()
        self.experts = self._build_experts()

    def _init_backend(self):
        backend = self.config.backend
        if not backend:
            raise RuntimeError(
                "未找到可用的 LLM 后端。\n"
                "  设置环境变量: LLM_BACKEND=deepseek  LLM_API_KEY=sk-...\n"
                "  或启动本地: LM Studio (localhost:1234) / Ollama (localhost:11434)"
            )
        self.client = AsyncOpenAI(
            api_key=backend.api_key,
            base_url=backend.base_url,
        )
        self.backend = backend

    @staticmethod
    def _build_experts() -> dict:
        from .experts import (
            ThreatIntelExpert,
            BeaconDetectorExpert,
            DNSTunnelExpert,
            PortScanExpert,
            ICMPTunnelExpert,
            PayloadExpert,
        )
        return {
            "ThreatIntelExpert": ThreatIntelExpert(),
            "BeaconDetectorExpert": BeaconDetectorExpert(),
            "DNSTunnelExpert": DNSTunnelExpert(),
            "PortScanExpert": PortScanExpert(),
            "ICMPTunnelExpert": ICMPTunnelExpert(),
            "PayloadExpert": PayloadExpert(),
        }

    async def analyze(self, session: dict[str, Any]) -> FinalReport:
        session_id = session.get("scenario", session.get("flow_key", "unknown"))

        dispatch = await self._dispatch(session)

        expert_results: dict[str, Any] = {}
        for expert_name in dispatch.get("experts_to_call", []):
            expert = self.experts.get(expert_name)
            if expert is None:
                continue
            try:
                result = expert.analyze(session)
                expert_results[expert_name] = result
            except Exception:
                logger.exception("专家 %s 分析失败", expert_name)
                expert_results[expert_name] = f"Error: expert '{expert_name}' failed"

        report = await self._synthesize(session, expert_results)
        report.session_id = session_id
        report.dispatch_reasoning = dispatch.get("reasoning", "")
        report.expert_findings = expert_results
        return report

    async def _dispatch(self, session: dict[str, Any]) -> dict[str, Any]:
        summary = _format_session(session)
        max_chars = getattr(self.backend, "input_max_chars", SESSION_FORMAT_MAX_CHARS)
        if len(summary) > max_chars:
            summary = summary[:max_chars] + "\n... (截断)"

        try:
            response = await self.client.chat.completions.create(
                model=self.backend.model,
                messages=[
                    {"role": "system", "content": DISPATCH_PROMPT},
                    {"role": "user", "content": summary},
                ],
                temperature=self.backend.temperature,
                max_tokens=self.backend.max_tokens_dispatch,
            )
            raw = response.choices[0].message.content.strip()
            return _parse_json_response(raw)
        except Exception:
            logger.exception("LLM调度失败，返回默认结果")
            return {"reasoning": "LLM调度失败", "experts_to_call": [], "alert": False}

    async def _synthesize(
        self,
        session: dict[str, Any],
        expert_results: dict[str, Any],
    ) -> FinalReport:
        results_text = _format_expert_results(expert_results)

        session_text = _format_session(session)
        if len(session_text) > SESSION_SYNTH_MAX_CHARS:
            session_text = session_text[:SESSION_SYNTH_MAX_CHARS] + "\n... (截断)"

        prompt = SYNTHESIS_PROMPT.format(
            expert_results=results_text,
            session_summary=session_text,
        )
        if len(prompt) > PROMPT_MAX_CHARS:
            prompt = prompt[:PROMPT_MAX_CHARS]

        try:
            response = await self.client.chat.completions.create(
                model=self.backend.model,
                messages=[
                    {"role": "system", "content": "你是网络安全分析专家。严格输出 JSON。"},
                    {"role": "user", "content": prompt},
                ],
                temperature=self.backend.temperature,
                max_tokens=self.backend.max_tokens_synthesis,
            )
            raw = response.choices[0].message.content.strip()
            data = _parse_json_response(raw)
        except Exception:
            logger.exception("LLM综合失败，返回默认报告")
            data = {}

        packets = session.get("packets", [])
        timeline = ""
        if packets:
            timeline = (
                f"{packets[0].get('ts', 0):.0f}s - {packets[-1].get('ts', 0):.0f}s | "
                f"{len(packets)} packets"
            )

        return FinalReport(
            is_malicious=data.get("is_malicious", False),
            attack_type=data.get("attack_type", "Unknown"),
            threat_level=data.get("threat_level", "None"),
            confidence=data.get("confidence", 0.0),
            attck_techniques=data.get("attck_techniques", []),
            iocs=data.get("iocs", {}),
            timeline=timeline,
            recommendations=data.get("recommendations", []),
        )


def _parse_json_response(raw: str) -> dict[str, Any]:
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        raw = "\n".join(lines)
        if raw.lower().startswith("json"):
            raw = raw[4:].lstrip()
    return json.loads(raw) if raw else {}


def _format_session(session: dict[str, Any]) -> str:
    features = session.get("features", {})
    packets = session.get("packets", [])
    scenario = session.get("scenario", "")

    lines = [
        f"场景: {scenario or session.get('flow_key', 'Unknown')}",
        f"描述: {session.get('description', '')}",
        f"包数量: {len(packets)}",
    ]

    if features:
        lines.append("特征:")
        for k, v in features.items():
            if isinstance(v, float):
                lines.append(f"  {k}: {v:.3f}")
            elif isinstance(v, list):
                lines.append(f"  {k}: {v}")
            else:
                lines.append(f"  {k}: {v}")

    if packets:
        lines.append(f"\n数据包样本 (前{PACKET_SAMPLE_COUNT}个):")
        for p in packets[:PACKET_SAMPLE_COUNT]:
            lines.append(
                f"  t={p['ts']:.2f}s  {p['src']}:{p['sport']} → "
                f"{p['dst']}:{p['dport']}  "
                f"proto={p['protocol']}  len={p['length']}  flags={p['flags']}"
            )

    return "\n".join(lines)


def _format_expert_results(expert_results: dict[str, Any]) -> str:
    parts = []
    for name, result in expert_results.items():
        parts.append(f"\n### {name}")
        if hasattr(result, "__dict__"):
            d = result.__dict__
            for k, v in d.items():
                if k.startswith("_"):
                    continue
                if isinstance(v, list) and v and len(str(v)) > 100:
                    parts.append(f"  {k}: {v[:3]}...")
                else:
                    parts.append(f"  {k}: {v}")
        else:
            parts.append(f"  {result}")
    return "\n".join(parts)
