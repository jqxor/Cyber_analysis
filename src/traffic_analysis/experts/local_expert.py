"""本地小LLM专家 - Ollama OpenAI兼容API"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from openai import AsyncOpenAI

from ..logger import get_logger

logger = get_logger(__name__)

TRIAGE_PROMPT = """你是流量安全初筛员。判断以下会话是否为**真实攻击**或**需深入分析的严重异常**。

排除这些明显误报:
- 正常的 Web 浏览 (HTTP 80/443, 少量包)
- 正常的 DNS 查询 (短查询名, 低频率)
- 内网设备间正常通信
- 已知的正常服务心跳

保留 (标记为需要深度分析):
- C2 Beacon 行为 (固定间隔心跳)
- 数据外泄 (大量上传, DNS 隧道, ICMP 隧道)
- 端口扫描/暴力破解
- 连接已知恶意 IP/域名
- 异常协议/端口组合
- 任何你觉得"不对劲"的模式

只输出 JSON，不要其他内容:
{"verdict": "escalate"|"pass", "confidence": 0.0-1.0, "reason": "一句话理由"}"""


@dataclass
class TriageResult:
    verdict: str = "pass"          # escalate(上报) | pass(放行)
    confidence: float = 0.0
    reason: str = ""
    raw_response: str = ""
    latency_ms: float = 0.0


class LocalTriageExpert:
    """本地小模型初筛 — 降低 API LLM 调用量"""

    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        model: str = "qwen2.5:1.5b",
        temperature: float = 0.0,
        max_tokens: int = 150,
        semaphore_limit: int = 10,
    ):
        self.client = AsyncOpenAI(base_url=base_url, api_key="ollama")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._semaphore = asyncio.Semaphore(semaphore_limit)
        self._stats = {"total": 0, "escalated": 0, "passed": 0, "errors": 0, "total_latency_ms": 0.0}

    @property
    def filter_rate(self) -> float:
        total = self._stats["total"]
        return self._stats["passed"] / max(total, 1) if total > 0 else 0.0

    @property
    def stats(self) -> dict:
        s = dict(self._stats)
        s["filter_rate"] = self.filter_rate
        s["avg_latency_ms"] = self._stats["total_latency_ms"] / max(self._stats["total"], 1)
        return s

    async def triage(self, session: dict[str, Any]) -> TriageResult:
        self._stats["total"] += 1
        start = time.perf_counter()

        async with self._semaphore:
            try:
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": TRIAGE_PROMPT},
                        {"role": "user", "content": _format_for_triage(session)},
                    ],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
                raw = response.choices[0].message.content.strip()
                data = _parse_json(raw)
            except Exception:
                logger.exception("本地模型错误")
                self._stats["errors"] += 1
                return TriageResult(verdict="pass", confidence=0.0, reason="model error")

        elapsed = (time.perf_counter() - start) * 1000
        self._stats["total_latency_ms"] += elapsed

        result = TriageResult(
            verdict=data.get("verdict", "pass"),
            confidence=data.get("confidence", 0.0),
            reason=data.get("reason", ""),
            raw_response=raw,
            latency_ms=elapsed,
        )

        if result.verdict == "escalate":
            self._stats["escalated"] += 1
        else:
            self._stats["passed"] += 1

        return result

    async def batch_triage(
        self, sessions: list[dict[str, Any]], verbose: bool = False
    ) -> list[tuple[dict, TriageResult]]:
        tasks = [self.triage(s) for s in sessions]
        results = await asyncio.gather(*tasks)
        pairs = list(zip(sessions, results))

        escalated = [p for p in pairs if p[1].verdict == "escalate"]
        logger.info(
            "批次完成: %d条 → %d条上报 (%d条过滤, %.0f%%过滤率)",
            len(sessions), len(escalated), len(sessions) - len(escalated),
            (len(sessions) - len(escalated)) / max(len(sessions), 1) * 100,
        )

        if verbose:
            for s, r in pairs:
                tag = "[>>]" if r.verdict == "escalate" else "[..]"
                key = s.get("scenario", s.get("flow_key", "?"))[:60]
                print(f"  {tag} {key} | {r.confidence:.0%} | {r.reason[:80]}")

        return pairs


def _format_for_triage(session: dict[str, Any]) -> str:
    features = session.get("features", {})
    packets = session.get("packets", [])
    scenario = session.get("scenario", session.get("flow_key", "Unknown"))
    desc = session.get("description", "")

    lines = [
        f"会话: {scenario}",
        f"描述: {desc}",
        f"包数: {len(packets)}",
    ]

    # 关键特征
    key_fields = [
        "duration_sec", "total_bytes", "upload_ratio",
        "beacon_score", "syn_ratio", "rst_ratio",
        "unique_ports", "packet_size_mean", "packet_size_std",
        "protocols", "port_list", "app_protocol",
    ]
    present = {k: features[k] for k in key_fields if k in features}
    if present:
        for k, v in present.items():
            if isinstance(v, float):
                lines.append(f"  {k}: {v:.3f}")
            elif isinstance(v, list):
                lines.append(f"  {k}: {v}")
            else:
                lines.append(f"  {k}: {v}")

    # 前5个数据包
    if packets:
        lines.append("报文样本 (前5):")
        for p in packets[:5]:
            lines.append(
                f"  t={p['ts']:.2f}s {p['src']}:{p['sport']} -> "
                f"{p['dst']}:{p['dport']} proto={p['protocol']} "
                f"len={p['length']}"
            )

    text = "\n".join(lines)
    # 小模型上下文有限, 截断
    return text[:1200]


def _parse_json(raw: str) -> dict[str, Any]:
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        raw = "\n".join(lines)
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {"verdict": "pass", "confidence": 0.0, "reason": raw[:100]}
