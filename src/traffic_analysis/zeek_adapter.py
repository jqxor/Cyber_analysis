import asyncio
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from src.traffic_analysis.llm_config import Config
from src.traffic_analysis.logger import get_logger
from src.traffic_analysis.orchestrator import LLMOrchestrator
from src.traffic_analysis.report_formatter import format_zeek_finding

from .constants import (
    BRUTEFORCE_PORTS,
    SUSPICIOUS_PORTS,
    ZEEK_ANOMALY_THRESHOLD,
    ZEEK_BASELINE_PCT_THRESHOLD,
)

logger = get_logger(__name__)

ZEEK_LOG_FIELDS: dict[str, list[str]] = {
    "conn": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "duration", "orig_bytes", "resp_bytes",
        "conn_state", "local_orig", "local_resp", "missed_bytes",
        "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    ],
    "dns": [
        "ts", "uid", "id.orig_h", "id.resp_h", "proto",
        "query", "qtype_name", "rcode_name", "answers",
    ],
    "http": [
        "ts", "uid", "id.orig_h", "id.resp_h", "method", "host",
        "uri", "status_code", "request_body_len", "response_body_len",
    ],
    "ssl": [
        "ts", "uid", "id.orig_h", "id.resp_h", "version",
        "cipher", "server_name", "ja3", "ja3s", "issuer",
    ],
    "notice": [
        "ts", "uid", "id.orig_h", "id.resp_h", "note", "msg", "sub", "src",
    ],
}

NORMAL_PORTS = {80, 443, 53, 8080, 8443}


@dataclass
class ZeekConn:
    uid: str
    ts: float
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    service: str
    duration: float
    orig_bytes: int
    resp_bytes: int
    conn_state: str
    orig_pkts: int
    resp_pkts: int
    history: str
    tunnel_parents: list[str] = field(default_factory=list)


@dataclass
class AnomalyEvent:
    ts: float
    score: float
    category: str
    conn: ZeekConn
    evidence: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)


class ZeekAdapter:
    def __init__(self, log_dir: str = "/usr/local/zeek/logs/current"):
        self.log_dir = Path(log_dir)
        self.baseline: dict = {}
        self.baseline_ready = False
        self.baseline_samples = 0

    def read_conn_log(self) -> list[ZeekConn]:
        conns: list[ZeekConn] = []
        fp = self.log_dir / "conn.log"
        if not fp.exists():
            logger.warning("conn.log 不存在: %s", fp)
            return conns

        with open(fp, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                conn = self._parse_conn_line(line)
                if conn is not None:
                    conns.append(conn)
        return conns

    @staticmethod
    def _parse_conn_line(line: str) -> Optional[ZeekConn]:
        try:
            fields = line.strip().split("\t")
            if len(fields) < 20:
                return None
            return ZeekConn(
                uid=fields[1],
                ts=float(fields[0]),
                orig_h=fields[2],
                orig_p=int(fields[3]),
                resp_h=fields[4],
                resp_p=int(fields[5]),
                proto=fields[6],
                service=fields[7] if len(fields) > 7 else "",
                duration=float(fields[8]) if fields[8] != "-" else 0,
                orig_bytes=int(fields[9]) if fields[9] != "-" else 0,
                resp_bytes=int(fields[10]) if fields[10] != "-" else 0,
                conn_state=fields[11],
                orig_pkts=int(fields[16]) if len(fields) > 16 and fields[16] != "-" else 0,
                resp_pkts=int(fields[18]) if len(fields) > 18 and fields[18] != "-" else 0,
                history=fields[15] if len(fields) > 15 else "",
            )
        except (ValueError, IndexError):
            return None

    def build_baseline(self, conns: list[ZeekConn]) -> None:
        profiles: dict = defaultdict(
            lambda: {"count": 0, "bytes_out": [], "bytes_in": [], "durations": [], "ports": set()}
        )

        for c in conns:
            key = (c.orig_h, c.resp_h, c.proto)
            p = profiles[key]
            p["count"] += 1
            p["bytes_out"].append(c.orig_bytes)
            p["bytes_in"].append(c.resp_bytes)
            p["durations"].append(c.duration)
            p["ports"].add(c.resp_p)

        for p in profiles.values():
            p["bytes_out"] = sorted(p["bytes_out"])
            p["bytes_in"] = sorted(p["bytes_in"])
            p["durations"] = sorted(p["durations"])

        self.baseline = dict(profiles)
        self.baseline_ready = True

    def detect_anomalies(self, conns: list[ZeekConn]) -> list[AnomalyEvent]:
        if not self.baseline_ready:
            return []

        events: list[AnomalyEvent] = []
        conn_rate: dict[tuple, int] = defaultdict(int)
        for c in conns:
            conn_rate[(c.orig_h, c.resp_h, c.resp_p)] += 1

        for c in conns:
            score = 0.0
            evidence: list[str] = []
            key = (c.orig_h, c.resp_h, c.proto)
            profile = self.baseline.get(key)

            if c.conn_state in ("S0", "S1", "REJ"):
                score += 0.15
                evidence.append(f"连接未建立: {c.conn_state}")

            if c.resp_p in BRUTEFORCE_PORTS:
                rate = conn_rate.get((c.orig_h, c.resp_h, c.resp_p), 1)
                if rate > 3:
                    score += 0.4
                    evidence.append(f"高频连接: {rate}次到端口{c.resp_p}")

            if c.resp_p not in NORMAL_PORTS and c.orig_bytes > 5000 and c.resp_bytes < 500:
                score += 0.2
                evidence.append(f"不对称传输: {c.orig_bytes}B↑/{c.resp_bytes}B↓")

            if profile:
                if c.orig_bytes > 0 and profile["bytes_out"]:
                    pct = sum(
                        1 for b in profile["bytes_out"] if b <= c.orig_bytes
                    ) / len(profile["bytes_out"])
                    if pct > ZEEK_BASELINE_PCT_THRESHOLD:
                        score += 0.1
                        evidence.append(f"出站流量异常 ({pct:.0%}分位)")

            if score > ZEEK_ANOMALY_THRESHOLD:
                events.append(
                    AnomalyEvent(
                        ts=c.ts,
                        score=min(score, 1.0),
                        category=self._categorize(c, evidence),
                        conn=c,
                        evidence=evidence,
                    )
                )

        return events

    @staticmethod
    def _categorize(c: ZeekConn, evidence: list[str]) -> str:
        for e in evidence:
            if "端口" in e and any(p in e for p in ("22", "21", "3389")):
                return "BruteForce"
        if c.resp_p in SUSPICIOUS_PORTS:
            return "C2_Channel"
        if c.resp_p == 53 and c.orig_bytes > 500:
            return "DNS_Tunnel"
        if c.proto == "icmp" and c.orig_bytes > 200:
            return "ICMP_Tunnel"
        if c.orig_bytes > c.resp_bytes * 5 and c.orig_bytes > 50000:
            return "Data_Exfil"
        return "Anomaly"


class ZeekOrchestrator:
    def __init__(self, log_dir: str):
        self.adapter = ZeekAdapter(log_dir)
        self.orchestrator: Optional[LLMOrchestrator] = None
        self.reports: list[dict] = []

    async def start(self) -> list[dict]:
        config = Config()
        if not config.is_ready:
            config.auto_detect()
        if not config.is_ready:
            raise RuntimeError("No LLM backend available")

        self.orchestrator = LLMOrchestrator(config)

        conns = self.adapter.read_conn_log()
        logger.info("读取 %d 条连接", len(conns))
        print(f"[Zeek] 读取 {len(conns)} 条连接")

        split = min(3000, len(conns) // 3)
        baseline_conns = conns[:split]
        test_conns = conns[split:]

        self.adapter.build_baseline(baseline_conns)
        logger.info("基线: %d条, %d个画像", len(baseline_conns), len(self.adapter.baseline))
        print(f"[Zeek] 基线: {len(baseline_conns)}条, {len(self.adapter.baseline)}个画像")

        events = self.adapter.detect_anomalies(test_conns)
        logger.info("异常: %d条 / %d条", len(events), len(test_conns))
        print(f"[Zeek] 异常: {len(events)}条 / {len(test_conns)}条")

        events.sort(key=lambda e: e.score, reverse=True)
        for i, ev in enumerate(events[:15]):
            session = self._event_to_session(ev)
            try:
                report = await self.orchestrator.analyze(session)
                self.reports.append({"event": ev, "report": report})
                print(format_zeek_finding(report, ev))
            except Exception:
                logger.exception("LLM分析失败 [%d]", i)

        return self.reports

    @staticmethod
    def _event_to_session(ev: AnomalyEvent) -> dict[str, Any]:
        c = ev.conn
        return {
            "scenario": f"Zeek Anomaly: {ev.category}",
            "description": (
                f"{ev.category} | {c.orig_h}:{c.orig_p}→{c.resp_h}:{c.resp_p} "
                f"[{c.proto}] | {c.orig_bytes}B↑/{c.resp_bytes}B↓ | {c.conn_state}"
            ),
            "risk_score": ev.score,
            "features": {
                "packet_count": c.orig_pkts + c.resp_pkts,
                "duration_sec": c.duration,
                "total_bytes": c.orig_bytes + c.resp_bytes,
                "out_bytes": c.orig_bytes,
                "in_bytes": c.resp_bytes,
                "upload_ratio": c.orig_bytes / max(c.orig_bytes + c.resp_bytes, 1),
                "unique_ports": 1,
                "protocols": [c.proto],
                "syn_ratio": 1.0 if c.conn_state in ("S0", "S1") else 0.0,
            },
            "packets": [
                {
                    "ts": c.ts,
                    "src": c.orig_h,
                    "dst": c.resp_h,
                    "sport": c.orig_p,
                    "dport": c.resp_p,
                    "protocol": c.proto,
                    "length": max(c.orig_bytes, c.resp_bytes),
                    "flags": 2 if c.conn_state in ("S0", "S1") else 24,
                    "direction": "out",
                }
            ],
        }


async def main() -> None:
    log_dir = os.environ.get("ZEEK_LOG_DIR", "/usr/local/zeek/logs/current")
    zo = ZeekOrchestrator(log_dir)
    await zo.start()


if __name__ == "__main__":
    asyncio.run(main())
