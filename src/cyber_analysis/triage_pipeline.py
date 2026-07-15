"""双层漏斗管道 - Tier1(local LLM) -> Tier2(API LLM)"""

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .config_manager import ConfigManager
from .experts.local_expert import LocalTriageExpert, TriageResult
from .flow_loader import FlowLoader, flow_to_session
from .llm_config import Config
from .logger import get_logger
from .orchestrator import LLMOrchestrator, FinalReport
from .session_loader import load_json_sessions_daemon
from .report_formatter import format_separator

logger = get_logger("pipeline")

SCANNABLE_EXTS = {".csv", ".json", ".pcap", ".pcapng", ".cap"}


class TriagePipeline:
    def __init__(
        self,
        input_dir: str = "./input",
        output_dir: str = "./output",
        local_model: str = "qwen2.5:1.5b",
        local_base_url: str = "http://localhost:11434/v1",
        local_concurrency: int = 200,
        max_api_calls_per_file: int = 50,
        verbose: bool = True,
    ):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.max_api_calls = max_api_calls_per_file
        self.verbose = verbose

        # Tier 1: 本地小模型
        self.triage = LocalTriageExpert(
            base_url=local_base_url,
            model=local_model,
            semaphore_limit=local_concurrency,
        )

        # Tier 2: API 大模型 (延迟初始化)
        self._orchestrator: Optional[LLMOrchestrator] = None

        self.input_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def _ensure_orchestrator(self) -> LLMOrchestrator:
        if self._orchestrator is None:
            config = Config()
            if not config.is_ready:
                config.auto_detect()
            if not config.is_ready:
                raise RuntimeError("无可用 API LLM 后端, 请配置 config.toml [backend]")
            self._orchestrator = LLMOrchestrator(config)
        return self._orchestrator

    async def run(self, watch: bool = False, interval: int = 30) -> dict:
        if watch:
            return await self._run_daemon(interval)
        return await self._run_once()

    async def _run_once(self) -> dict:
        files = self._discover_files()
        if not files:
            print(f"  [i] 无待处理文件: {self.input_dir}")
            return {"files": 0, "sessions": 0, "escalated": 0, "reports": 0}

        stats = {"files": 0, "sessions": 0, "escalated": 0, "reports": 0}
        for fp in files:
            file_stats = await self._process_file(fp)
            for k in stats:
                stats[k] += file_stats.get(k, 0)

        self._print_pipeline_summary(stats)
        return stats

    async def _run_daemon(self, interval: int) -> dict:
        import sys

        total = {"files": 0, "sessions": 0, "escalated": 0, "reports": 0}
        print(f"  [OK] 管道守护已启动, 监控: {self.input_dir}\n")

        processed: set[str] = set()
        state_file = self.input_dir / ".pipeline_state.json"
        if state_file.exists():
            processed = set(json.loads(state_file.read_text()))

        try:
            while True:
                files = [f for f in self._discover_files() if str(f) not in processed]
                if files:
                    for fp in files:
                        file_stats = await self._process_file(fp)
                        for k in total:
                            total[k] += file_stats.get(k, 0)
                        processed.add(str(fp))
                        state_file.write_text(json.dumps(list(processed)))
                else:
                    sys.stdout.write(
                        f"\r  [{_ts(True)}] 等待中... "
                        f"已处理 {total['files']}文件/{total['sessions']}流/{total['reports']}报告  "
                    )
                    sys.stdout.flush()
                await asyncio.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n\n  [X] 管道已停止")
        finally:
            self._print_pipeline_summary(total)
        return total

    async def _process_file(self, fp: Path) -> dict:
        tag = f"[{fp.suffix.upper()[1:]}]"
        size_mb = fp.stat().st_size / 1024 / 1024
        print(f"\n{format_separator()}")
        print(f"  {tag} {fp.name} ({size_mb:.1f}MB)")
        print(f"{format_separator()}")
        logger.info("处理文件: %s", fp.name)

        t0 = time.time()

        # 1) 提取 sessions
        sessions = self._extract_sessions(fp)
        if not sessions:
            print(f"  [W] 未提取到有效流")
            return {"files": 1, "sessions": 0, "escalated": 0, "reports": 0}

        print(f"  [+] 提取 {len(sessions)} 条会话")

        print(f"  [*] Tier 1: 本地小模型初筛 ({self.triage.model})...")
        t1_start = time.time()
        pairs = await self.triage.batch_triage(sessions, verbose=self.verbose)
        t1_elapsed = time.time() - t1_start

        escalated = [s for s, r in pairs if r.verdict == "escalate"]
        passed = len(sessions) - len(escalated)

        print(f"  [OK] Tier 1 完成 ({t1_elapsed:.1f}s): "
              f"上报 {len(escalated)} | 过滤 {passed} "
              f"({passed/max(len(sessions),1)*100:.0f}%)")

        if not escalated:
            self._write_summary(fp, sessions, pairs)
            return {"files": 1, "sessions": len(sessions), "escalated": 0, "reports": 0}

        print(f"  [*] Tier 2: API 大模型深析 ({len(escalated)} 条)...")
        t2_start = time.time()
        reports = await self._deep_analyze(escalated)
        t2_elapsed = time.time() - t2_start

        # 4) 写报告
        self._write_reports(fp, escalated, reports, pairs)
        self._write_summary(fp, sessions, pairs, reports)

        total_elapsed = time.time() - t0
        malicious = sum(1 for r in reports if r and r.is_malicious)
        api_calls = len(escalated)

        print(f"  [OK] 完成 ({total_elapsed:.1f}s): "
              f"T1={t1_elapsed:.1f}s T2={t2_elapsed:.1f}s | "
              f"API调用={api_calls} | 确认恶意={malicious}")

        return {
            "files": 1,
            "sessions": len(sessions),
            "escalated": len(escalated),
            "reports": len(reports),
        }

    async def _deep_analyze(self, sessions: list[dict]) -> list[Optional[FinalReport]]:
        orch = await self._ensure_orchestrator()
        tasks = []
        for i, s in enumerate(sessions):
            if i >= self.max_api_calls:
                break
            tasks.append(self._analyze_one(orch, s))
        return await asyncio.gather(*tasks)

    async def _analyze_one(self, orch: LLMOrchestrator, session: dict) -> Optional[FinalReport]:
        try:
            return await orch.analyze(session)
        except Exception:
            logger.exception("API 分析失败")
            return None

    def _extract_sessions(self, fp: Path) -> list[dict]:
        ext = fp.suffix.lower()
        if ext == ".json":
            return load_json_sessions_daemon(fp)
        if ext == ".csv":
            loader = FlowLoader(str(fp))
            return [flow_to_session(f) for f in loader.filter_suspicious(min_score=0.1)]
        if ext in (".pcap", ".pcapng", ".cap"):
            from .pcap_analyzer import analyze_pcap
            return analyze_pcap(str(fp))
        return []

    def _write_reports(
        self,
        fp: Path,
        sessions: list[dict],
        reports: list[Optional[FinalReport]],
        triage_pairs: list,
    ) -> None:
        alerts = []
        for s, report in zip(sessions, reports):
            if report is None:
                continue
            # 找到对应的 triage 结果
            triage_result = None
            for ts, tr in triage_pairs:
                if ts is s:
                    triage_result = tr
                    break

            alerts.append({
                "session": s.get("scenario", s.get("flow_key", "")),
                "description": s.get("description", ""),
                "triage_verdict": triage_result.verdict if triage_result else "?",
                "triage_reason": triage_result.reason if triage_result else "",
                "is_malicious": report.is_malicious,
                "attack_type": report.attack_type,
                "threat_level": report.threat_level,
                "confidence": report.confidence,
                "attck_techniques": report.attck_techniques,
                "iocs": report.iocs,
                "recommendations": report.recommendations,
                "dispatch_reasoning": report.dispatch_reasoning,
            })

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.output_dir / f"{fp.stem}_{ts}_alerts.json"
        report_path.write_text(
            json.dumps({
                "input_file": fp.name,
                "analyzed_at": datetime.now().isoformat(),
                "pipeline": "Tier1(LocalLLM) → Tier2(API LLM)",
                "total_sessions": len(triage_pairs),
                "escalated_to_tier2": len(sessions),
                "total_alerts": len(alerts),
                "alerts": alerts,
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"  [+] 告警报告: {report_path}")

    def _write_summary(
        self,
        fp: Path,
        all_sessions: list[dict],
        triage_pairs: list,
        reports: list | None = None,
    ) -> None:
        triage_summary = {
            "total": len(triage_pairs),
            "escalated": sum(1 for _, r in triage_pairs if r.verdict == "escalate"),
            "passed": sum(1 for _, r in triage_pairs if r.verdict == "pass"),
            "avg_confidence": sum(r.confidence for _, r in triage_pairs) / max(len(triage_pairs), 1),
        }

        if reports:
            triage_summary["malicious_confirmed"] = sum(
                1 for r in reports if r and r.is_malicious
            )

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_path = self.output_dir / f"{fp.stem}_{ts}_summary.json"
        summary_path.write_text(
            json.dumps({
                "input_file": fp.name,
                "model_tier1": self.triage.model,
                "processed_at": datetime.now().isoformat(),
                "triage_stats": self.triage.stats,
                "file_summary": triage_summary,
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _discover_files(self) -> list[Path]:
        items: list[Path] = []
        for ext in SCANNABLE_EXTS:
            items.extend(sorted(self.input_dir.glob(f"*{ext}")))
        return [f for f in items if f.name not in (".scan_state.json", ".pipeline_state.json")]

    def _print_pipeline_summary(self, stats: dict) -> None:
        ts = self.triage.stats
        print(f"\n{format_separator()}")
        print(f"  [=] 管道统计")
        print(f"      文件: {stats['files']}")
        print(f"      会话: {stats['sessions']}")
        print(f"      Tier1→Tier2: {stats['escalated']}")
        print(f"      报告产出: {stats['reports']}")
        print(f"      过滤率: {ts['filter_rate']:.0%} "
              f"(Tier1 均延迟: {ts['avg_latency_ms']:.0f}ms)")
        print(f"{format_separator()}")


def _ts(short: bool = False) -> str:
    fmt = "%H:%M:%S" if short else "%Y-%m-%d %H:%M:%S"
    return datetime.now().strftime(fmt)
