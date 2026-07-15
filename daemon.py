import asyncio
import json
import random
import sys
import time
from datetime import datetime
from pathlib import Path

from src.traffic_analysis.flow_loader import FlowLoader, flow_to_session
from src.traffic_analysis.llm_config import Config
from src.traffic_analysis.logger import setup_file_logging, get_logger
from src.traffic_analysis.orchestrator import LLMOrchestrator, FinalReport
from src.traffic_analysis.session_loader import load_json_sessions_daemon

logger = get_logger("daemon")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class WatchDaemon:
    def __init__(self, watch_dir: str, interval: int = 30, max_per_scan: int = 20):
        self.watch_dir = Path(watch_dir)
        self.interval = interval
        self.max_per_scan = max_per_scan
        self.processed: set[str] = set()
        self.state_file = self.watch_dir / ".scan_state.json"
        self.report_dir = self.watch_dir / "reports"
        self.orchestrator: LLMOrchestrator | None = None
        self.running = False
        self.stats = {
            "total_files": 0,
            "total_flows": 0,
            "alerts": 0,
            "last_scan": None,
        }

        setup_file_logging(self.watch_dir / "logs")

    def _load_state(self) -> None:
        if self.state_file.exists():
            self.processed = set(json.loads(self.state_file.read_text()))

    def _save_state(self) -> None:
        self.state_file.write_text(json.dumps(list(self.processed)))

    async def start(self) -> None:
        config = Config()
        if not config.is_ready:
            config.auto_detect()
        if not config.is_ready:
            logger.error("无可用 LLM 后端")
            print(f"[{_now()}] ❌ 无可用 LLM")
            return

        self.orchestrator = LLMOrchestrator(config)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self._load_state()
        self.running = True

        print(f"[{_now()}] 🟢 守护进程启动")
        print(f"    监控目录: {self.watch_dir}")
        print(f"    扫描间隔: {self.interval}s")
        print(f"    每次最多: {self.max_per_scan} 条")
        print(f"    LLM后端: {config.backend.name}")
        logger.info("守护进程启动: %s 间隔=%ds 上限=%d", self.watch_dir, self.interval, self.max_per_scan)

        while self.running:
            try:
                await self._scan()
            except Exception:
                logger.exception("扫描异常")
            await asyncio.sleep(self.interval)

    async def _scan(self) -> None:
        files = list(self.watch_dir.glob("*"))
        csv_files = [
            f for f in files
            if f.suffix in (".csv", ".json") and f.name != ".scan_state.json"
        ]
        new_files = [
            f for f in csv_files
            if str(f) not in self.processed and f.stat().st_size > 0
        ]

        if new_files:
            print(f"\n[{_now()}] 📂 发现 {len(new_files)} 个新文件")
            for fp in new_files:
                await self._process_file(fp)
        else:
            ts = datetime.now().strftime("%H:%M:%S")
            sys.stdout.write(
                f"\r[{ts}] 💤 无新文件, "
                f"总计处理: {self.stats['total_files']}文件/"
                f"{self.stats['total_flows']}流/"
                f"{self.stats['alerts']}告警  "
            )
            sys.stdout.flush()

    async def _process_file(self, fp: Path) -> None:
        file_size_mb = fp.stat().st_size / 1024 / 1024
        print(f"  📄 {fp.name} ({file_size_mb:.1f}MB)")
        logger.info("处理文件: %s (%.1fMB)", fp.name, file_size_mb)
        start = time.time()

        sessions = self._load_sessions(fp)
        if not sessions:
            print("    ✅ 无可疑流")
            self._mark_processed(fp)
            return

        alerts = await self._analyze_sessions(sessions)
        self._finalize_file(fp, sessions, alerts, start)

    def _load_sessions(self, fp: Path) -> list[dict]:
        if fp.suffix == ".json":
            return load_json_sessions_daemon(fp)

        loader = FlowLoader(str(fp))
        sessions = []
        for flow in loader.filter_suspicious(min_score=0.1):
            sessions.append(flow_to_session(flow))

        if len(sessions) > self.max_per_scan:
            random.seed(42)
            sessions = random.sample(sessions, self.max_per_scan)
        return sessions

    async def _analyze_sessions(self, sessions: list[dict]) -> list[dict]:
        alerts: list[dict] = []
        for i, session in enumerate(sessions):
            try:
                report: FinalReport = await self.orchestrator.analyze(session)
                if report.is_malicious:
                    src_ip = "unknown"
                    dst_ip = "unknown"
                    dst_port = 0
                    pkts = session.get("packets", [])
                    if pkts:
                        src_ip = pkts[0].get("src", "unknown")
                        dst_ip = pkts[0].get("dst", "unknown")
                        dst_port = pkts[0].get("dport", 0)
                    alerts.append({
                        "target_ip": dst_ip,
                        "target_port": dst_port,
                        "attacker_ip": src_ip,
                        "attack_type": report.attack_type,
                        "threat_level": report.threat_level,
                        "confidence": report.confidence,
                        "attck_techniques": report.attck_techniques,
                        "iocs": report.iocs,
                        "evidence": report.dispatch_reasoning,
                        "recommended_action": report.recommendations[0] if report.recommendations else "",
                        "time_window": session.get("features", {}).get("duration_sec", 0),
                    })
                self.stats["total_flows"] += 1
            except Exception:
                logger.exception("分析错误 [%d/%d]", i + 1, len(sessions))

            if (i + 1) % 5 == 0:
                print(f"    ... {i+1}/{len(sessions)}")
        return alerts

    def _finalize_file(
        self, fp: Path, sessions: list[dict], alerts: list[dict], start: float
    ) -> None:
        self.stats["total_files"] += 1
        self.stats["alerts"] += len(alerts)
        self._mark_processed(fp)
        self._save_state()

        elapsed = time.time() - start
        print(f"    ✅ 完成: {len(sessions)}条/{elapsed:.1f}s, 告警: {len(alerts)}")

        if alerts:
            self._write_report(fp.stem, alerts)

    def _write_report(self, name: str, alerts: list[dict]) -> None:
        aggregated = self._aggregate(alerts)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.report_dir / f"{name}_{timestamp}.json"

        by_type = {}
        for a in aggregated:
            t = a.get("attack_type", "Unknown")
            by_type[t] = by_type.get(t, 0) + 1
        by_level = {}
        for a in aggregated:
            lvl = a.get("threat_level", "Low")
            by_level[lvl] = by_level.get(lvl, 0) + 1

        report_path.write_text(
            json.dumps({
                "analysis_time": datetime.now().isoformat(),
                "input_file": name,
                "total_alerts": len(aggregated),
                "statistics": {"by_type": by_type, "by_level": by_level},
                "alerts": aggregated,
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"    📋 报告: {report_path}")

    def _aggregate(self, alerts: list[dict]) -> list[dict]:
        groups = {}
        for a in alerts:
            key = (a.get("target_ip","?"), a.get("target_port",0), a.get("attack_type","?"))
            if key in groups:
                g = groups[key]
                g["request_count"] = g.get("request_count", 1) + a.get("request_count", 1)
                g["confidence"] = max(g.get("confidence", 0), a.get("confidence", 0))
                if a.get("threat_level") == "Critical":
                    g["threat_level"] = "Critical"
            else:
                a.setdefault("request_count", 1)
                groups[key] = a
        return sorted(groups.values(), key=lambda x: x.get("confidence", 0), reverse=True)

    def _mark_processed(self, fp: Path) -> None:
        self.processed.add(str(fp))

    def stop(self) -> None:
        self.running = False
        logger.info("守护进程停止")
        print(f"\n[{_now()}] 🔴 守护进程停止")


async def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="流量分析守护进程")
    parser.add_argument("--input", required=True, help="输入目录(只读)")
    parser.add_argument("--output", required=True, help="输出目录(只写)")
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--max", type=int, default=20)
    args = parser.parse_args()

    daemon = WatchDaemon(args.input, args.interval, args.max)
    daemon.report_dir = Path(args.output)
    try:
        await daemon.start()
    except KeyboardInterrupt:
        daemon.stop()


if __name__ == "__main__":
    asyncio.run(main())
