"""Traffic Analysis CLI"""

import argparse
import asyncio
import json
import os
import random
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from .config_manager import ConfigManager
from .logger import setup_file_logging, get_logger
from .report_formatter import format_separator

VERSION = "0.2.0"
logger = get_logger("cli")

SCANNABLE_EXTS = {".csv", ".json", ".pcap", ".pcapng", ".cap"}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="traffic-analyze",
        description="流量分析系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="store_true", help="显示版本号")
    sub = parser.add_subparsers(dest="command", title="子命令")

    p_scan = sub.add_parser("scan", help="分析流量 (自动识别文件/目录/格式)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="traffic-analyze scan data.csv --max 30")
    p_scan.add_argument("path", nargs="?", default=".", help="文件或目录路径")
    p_scan.add_argument("--max", "-m", type=int, default=50, help="最大 LLM 调用次数")
    p_scan.add_argument("--backend", "-b", help="指定后端")

    p_ids = sub.add_parser("analyze-ids", help="分析 CIC-IDS2018 CSV (含标签对比)")
    p_ids.add_argument("csv", help="CSV 文件路径")
    p_ids.add_argument("--max", "-m", type=int, default=50, help="最大 LLM 调用次数")

    p_daemon = sub.add_parser("daemon", help="启动文件监控守护进程")
    p_daemon.add_argument("--watch", "-w", default="./data", help="监控目录")
    p_daemon.add_argument("--interval", "-i", type=int, default=30, help="扫描间隔秒")
    p_daemon.add_argument("--max", "-m", type=int, default=20, help="每次最多分析条数")

    p_pipe = sub.add_parser("pipeline", help="双层漏斗管道 (本地LLM初筛 -> API LLM深析)")
    p_pipe.add_argument("--input", "-i", default=None, help="输入目录")
    p_pipe.add_argument("--output", "-o", default=None, help="输出目录")
    p_pipe.add_argument("--watch", "-w", action="store_true", help="持续监控模式")
    p_pipe.add_argument("--interval", type=int, default=30, help="监控间隔秒")
    p_pipe.add_argument("--model", default=None, help="本地模型名")
    p_pipe.add_argument("--max", "-m", type=int, default=None, help="每文件最大 API 调用")

    p_cfg = sub.add_parser("config", help="管理配置")
    cfg_sub = p_cfg.add_subparsers(dest="config_action")
    cfg_sub.add_parser("show", help="显示当前配置")
    cfg_set = cfg_sub.add_parser("set", help="修改配置项")
    cfg_set.add_argument("key", help="配置项 (如 backend.provider)")
    cfg_set.add_argument("value", help="配置值")
    cfg_sub.add_parser("init", help="重新生成 config.toml")
    cfg_sub.add_parser("path", help="显示配置文件路径")

    sub.add_parser("list-experts", help="列出所有可用的专家检测模块")
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    if args.version:
        print(f"traffic-analyze v{VERSION}")
        return
    if args.command is None:
        parser.print_help()
        return
    {
        "scan": _cmd_scan, "analyze-ids": _cmd_analyze_ids, "daemon": _cmd_daemon,
        "pipeline": _cmd_pipeline, "config": _cmd_config, "list-experts": _cmd_list_experts,
    }.get(args.command, lambda _: parser.print_help())(args)


def _ensure_backend() -> "Config":
    from .llm_config import Config
    config = Config()
    if not config.is_ready:
        config.auto_detect()
    if not config.is_ready:
        print("  [!!] 未发现 LLM 后端: traffic-analyze config set backend.api_key <key>")
        sys.exit(1)
    return config


def _cmd_config(args) -> None:
    cfg = ConfigManager()
    if args.config_action is None:
        print(cfg.show())
        return
    actions = {
        "show": lambda: print(cfg.show()),
        "set": lambda: _config_set(cfg, args.key, args.value),
        "init": lambda: _config_init(cfg),
        "path": lambda: print(f"  [*] {cfg.config_path.resolve()}"),
    }
    act = actions.get(args.config_action)
    if act: act()
    else: print("  用法: traffic-analyze config {show|set|init|path}")


def _config_set(cfg: ConfigManager, key: str, value: str) -> None:
    from .config_manager import _CONF_KEYS
    if key not in _CONF_KEYS:
        print(f"  [!!] 未知: {key}")
        return
    cfg.set_and_save(key, value)
    v = cfg.get(key)
    if key == "backend.api_key": v = cfg.backend.masked_key
    print(f"  [OK] {key} = {v}")


def _config_init(cfg: ConfigManager) -> None:
    from .config_manager import _write_default_config
    _write_default_config(cfg.config_path)
    print(f"  [OK] 已初始化: {cfg.config_path}")


def _cmd_scan(args) -> None:
    target = args.path
    if not os.path.exists(target):
        print(f"  [!!] 路径不存在: {target}")
        return
    if os.path.isfile(target):
        ext = Path(target).suffix.lower()
        if ext not in SCANNABLE_EXTS:
            print(f"  [!!] 不支持: {ext} (支持 {', '.join(sorted(SCANNABLE_EXTS))})")
            return
        asyncio.run(_scan_file(target, args.max, args.backend))
        return
    if os.path.isdir(target):
        files = _discover_files(target)
        if not files:
            print(f"  [!!] 目录下无可分析文件: {target}")
            return
        print(f"  [i] 发现 {len(files)} 个文件: {', '.join(f.name for f in files)}")
        for fp in files:
            asyncio.run(_scan_file(str(fp), args.max, args.backend))
    else:
        print(f"  [!!] 无效路径: {target}")


def _discover_files(directory: str) -> list[Path]:
    d = Path(directory)
    items: list[Path] = []
    for ext in SCANNABLE_EXTS:
        items.extend(sorted(d.glob(f"*{ext}")))
    return [f for f in items if f.name != ".scan_state.json"]


async def _scan_file(filepath: str, max_calls: int, backend_override: Optional[str] = None) -> None:
    fp = Path(filepath)
    ext = fp.suffix.lower()
    print(format_separator())
    print(f"  [*] 流量分析 v{VERSION}  [+] 文件: {filepath}  [i] 最大调用: {max_calls}")
    print(format_separator())
    if ext == ".json":
        await _scan_json(fp, backend_override)
    elif ext == ".csv":
        await _scan_csv(fp, max_calls, labeled=False)
    elif ext in (".pcap", ".pcapng", ".cap"):
        await _scan_pcap(fp, max_calls)
    else:
        print(f"  [!!] 不支持的文件类型: {ext}")


async def _scan_json(fp: Path, backend_override: Optional[str] = None) -> None:
    from .session_loader import load_json_sessions
    from .orchestrator import LLMOrchestrator, FinalReport
    from .report_formatter import format_report_console

    config = _ensure_backend()
    if backend_override:
        config.set_backend(backend_override)
    print(f"  [*] 后端: {config.backend.name} | {config.backend.model}\n")

    sessions = load_json_sessions(str(fp))
    print(f"  [+] 加载 {len(sessions)} 个场景\n")
    orchestrator = LLMOrchestrator(config)
    stats = {"total": 0, "malicious": 0, "benign": 0}

    for i, session in enumerate(sessions):
        print(f"  [{i+1}/{len(sessions)}] 分析中...")
        try:
            report: FinalReport = await orchestrator.analyze(session)
            print(format_report_console(report, session))
            stats["total"] += 1
            if report.is_malicious: stats["malicious"] += 1
            else: stats["benign"] += 1
        except Exception:
            logger.exception("场景分析失败")

    print(format_separator())
    print(f"  [=] 总计 {stats['total']} | 恶意 {stats['malicious']} | 正常 {stats['benign']}")
    print(format_separator())


async def _scan_csv(fp: Path, max_calls: int, labeled: bool = False) -> None:
    from .flow_loader import FlowLoader, flow_to_session
    from .orchestrator import LLMOrchestrator, FinalReport
    from .report_formatter import format_report_console

    config = _ensure_backend()
    print(f"  [*] 后端: {config.backend.name} | {config.backend.model}\n")
    loader = FlowLoader(str(fp))
    if labeled:
        ld = loader.get_label_distribution()
        print(f"  总流数: {loader.total_flows:,}")
        for l, c in sorted(ld.items(), key=lambda x: -x[1])[:8]:
            print(f"    {l}: {c:,}")

    suspicious, labels = [], []
    for flow in loader.filter_suspicious(min_score=0.3):
        suspicious.append(flow_to_session(flow))
        labels.append(flow.get("_label", ""))
    print(f"  [+] 可疑流: {len(suspicious):,} / {loader.total_flows:,}")
    if not suspicious:
        print("  [W] 无可疑流"); return

    if len(suspicious) > max_calls:
        random.seed(42)
        indices = random.sample(range(len(suspicious)), max_calls)
        sampled = [suspicious[i] for i in indices]
        sampled_labels = [labels[i] for i in indices]
        print(f"  [i] 采样 {max_calls} 条")
    else:
        sampled, sampled_labels = suspicious, labels

    orchestrator = LLMOrchestrator(config)
    if labeled:
        await _run_labeled_analysis(orchestrator, sampled, sampled_labels)
    else:
        await _run_unlabeled_analysis(orchestrator, sampled)


async def _run_unlabeled_analysis(orchestrator, sessions: list) -> None:
    from .report_formatter import format_report_console
    stats = {"total": 0, "malicious": 0, "benign": 0}
    for i, s in enumerate(sessions):
        print(f"  [{i+1}/{len(sessions)}] 分析中...")
        try:
            report = await orchestrator.analyze(s)
            print(format_report_console(report, s))
            stats["total"] += 1
            if report.is_malicious: stats["malicious"] += 1
            else: stats["benign"] += 1
        except Exception:
            logger.exception("分析失败")
    print(format_separator())
    print(f"  [=] 总计 {stats['total']} | 恶意 {stats['malicious']} | 正常 {stats['benign']}")


async def _run_labeled_analysis(orchestrator, sessions: list, labels: list) -> None:
    stats = {"TP": 0, "TN": 0, "FP": 0, "FN": 0, "errors": 0}
    det_by_label = defaultdict(lambda: {"total": 0, "detected": 0})

    def _cat(lbl: str) -> str:
        lbl = lbl.lower()
        for kw, cat in [("benign", "Benign"), ("ddos","DoS/DDoS"), ("dos","DoS/DDoS"),
                         ("brute","BruteForce"), ("ftp","BruteForce"), ("ssh","BruteForce"),
                         ("bot","Botnet"), ("infiltrat","Infiltration")]:
            if kw in lbl: return cat
        return "WebAttack" if ("web" in lbl and ("sql" in lbl or "xss" in lbl)) else lbl

    start = time.time()
    for i, (session, lbl) in enumerate(zip(sessions, labels)):
        true_cat = _cat(lbl)
        det_by_label[true_cat]["total"] += 1
        try:
            report = await orchestrator.analyze(session)
            detected, real_mal = report.is_malicious, true_cat != "Benign"
            if detected and real_mal: stats["TP"] += 1
            elif detected and not real_mal: stats["FP"] += 1
            elif not detected and real_mal: stats["FN"] += 1
            else: stats["TN"] += 1
            if detected: det_by_label[true_cat]["detected"] += 1
            rate = (i + 1) / max(time.time() - start, 0.01)
            print(f"\r  [{i+1}/{len(sessions)}] {rate:.1f}/s | "
                  f"TP:{stats['TP']} FP:{stats['FP']} FN:{stats['FN']} TN:{stats['TN']}", end="")
        except Exception:
            stats["errors"] += 1

    elapsed = time.time() - start
    total = sum(v for k, v in stats.items() if k != "errors")
    print("\n\n" + format_separator())
    print("  [=] 分析结果 vs 标签")
    print(format_separator())
    if total > 0:
        acc = (stats["TP"] + stats["TN"]) / total
        prec = stats["TP"] / max(stats["TP"] + stats["FP"], 1)
        rec = stats["TP"] / max(stats["TP"] + stats["FN"], 1)
        f1 = 2 * prec * rec / max(prec + rec, 0.01)
        print(f"\n  Accuracy: {acc:.1%}  Precision: {prec:.1%}  Recall: {rec:.1%}  F1: {f1:.1%}")
    print(f"\n  TP:{stats['TP']} FP:{stats['FP']} FN:{stats['FN']} TN:{stats['TN']}")
    if det_by_label:
        print("\n  各类别检出率:")
        for cat in sorted(det_by_label):
            d = det_by_label[cat]
            rate = d["detected"] / max(d["total"], 1)
            bar = "#" * int(rate * 20) + "." * (20 - int(rate * 20))
            print(f"    {cat:<18s} {d['detected']:>4}/{d['total']:<4} {bar} {rate:.0%}")
    print(f"\n  耗时: {elapsed:.1f}s | 平均: {elapsed/max(len(sessions),1):.1f}s/条")
    print(format_separator())


async def _scan_pcap(fp: Path, max_calls: int) -> None:
    from .pcap_analyzer import analyze_pcap, TSHARK, SCAPY_AVAILABLE
    from .orchestrator import LLMOrchestrator

    print(f"  [*] PCAP: {fp.name}")
    tool = "tshark" if TSHARK else ("scapy" if SCAPY_AVAILABLE else "pure Python")
    print(f"  [OK] {tool}")
    sessions = analyze_pcap(str(fp))
    if not sessions:
        print("  [W] 未提取到有效流"); return
    print(f"  [+] 提取 {len(sessions)} 条流\n")

    if len(sessions) > max_calls:
        random.seed(42)
        sessions = random.sample(sessions, max_calls)
        print(f"  [i] 采样 {len(sessions)} 条")

    config = _ensure_backend()
    orchestrator = LLMOrchestrator(config)
    print(f"  [*] 后端: {config.backend.name} | {config.backend.model}\n")

    stats = {"total": 0, "malicious": 0, "benign": 0}
    icons = {"Critical": "[!!]", "High": "[W]", "Medium": "[i]", "Low": "[.]", "None": "   "}
    for s in sessions:
        try:
            report = await orchestrator.analyze(s)
            stats["total"] += 1
            if report.is_malicious: stats["malicious"] += 1
            else: stats["benign"] += 1
            print(f"  {icons.get(report.threat_level)} [{report.threat_level}] "
                  f"{s['scenario'][:50]} | {report.attack_type} | {report.confidence:.0%}")
        except Exception:
            pass
    print(f"\n  [=] 总计 {stats['total']} | 恶意 {stats['malicious']} | 正常 {stats['benign']}")


def _cmd_analyze_ids(args) -> None:
    if not os.path.exists(args.csv):
        print(f"  [!!] 文件不存在: {args.csv}"); return
    asyncio.run(_scan_csv(Path(args.csv), args.max, labeled=True))


def _cmd_daemon(args) -> None:
    print(format_separator())
    print(f"  [*] 守护进程 v{VERSION}  [+] 监控: {args.watch}  [i] 间隔: {args.interval}s")
    print(format_separator())
    asyncio.run(_daemon_async(args.watch, args.interval, args.max))


async def _daemon_async(watch_dir: str, interval: int, max_per: int) -> None:
    import asyncio as aio
    from .flow_loader import FlowLoader, flow_to_session
    from .session_loader import load_json_sessions_daemon
    from .orchestrator import LLMOrchestrator

    config = _ensure_backend()
    orchestrator = LLMOrchestrator(config)
    watch = Path(watch_dir)
    watch.mkdir(parents=True, exist_ok=True)
    report_dir = watch / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    state_file = watch / ".scan_state.json"
    processed = set(json.loads(state_file.read_text())) if state_file.exists() else set()
    tf, tfl, ta = 0, 0, 0
    print("  [OK] 已启动\n")

    try:
        while True:
            new = [f for f in _discover_files(str(watch)) if str(f) not in processed and f.stat().st_size > 0]
            if new:
                print(f"\n  [{_ts()}] [+] 发现 {len(new)} 个新文件")
                for fp in new:
                    size_mb = fp.stat().st_size / 1024 / 1024
                    print(f"    [+] {fp.name} ({size_mb:.1f}MB)")
                    t0 = time.time()
                    if fp.suffix == ".json":
                        sessions = load_json_sessions_daemon(fp)
                    else:
                        loader = FlowLoader(str(fp))
                        sessions = [flow_to_session(f) for f in loader.filter_suspicious(min_score=0.1)]
                        if len(sessions) > max_per:
                            random.seed(42)
                            sessions = random.sample(sessions, max_per)
                    if not sessions:
                        print("      [OK] 无可疑流"); processed.add(str(fp)); tf += 1; continue
                    alerts = []
                    for i, s in enumerate(sessions):
                        try:
                            report = await orchestrator.analyze(s)
                            if report.is_malicious:
                                alerts.append({"session": s.get("scenario", s.get("flow_key","")),
                                    "attack": report.attack_type, "level": report.threat_level,
                                    "confidence": report.confidence, "attck": report.attck_techniques,
                                    "iocs": report.iocs})
                            tfl += 1
                        except Exception:
                            pass
                        if (i+1) % 5 == 0: print(f"      ... {i+1}/{len(sessions)}")
                    tf += 1; ta += len(alerts); processed.add(str(fp))
                    state_file.write_text(json.dumps(list(processed)))
                    print(f"      [OK] {len(sessions)}条/{time.time()-t0:.1f}s, 告警: {len(alerts)}")
                    if alerts:
                        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                        rp = report_dir / f"{fp.stem}_{ts}.json"
                        rp.write_text(json.dumps({"file": fp.stem, "timestamp": datetime.now().isoformat(),
                            "total_alerts": len(alerts), "alerts": alerts}, ensure_ascii=False, indent=2), encoding="utf-8")
                        print(f"      [+] 报告: {rp}")
            else:
                sys.stdout.write(f"\r  [{_ts(True)}] [.] {tf}文件/{tfl}流/{ta}告警  "); sys.stdout.flush()
            await aio.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n\n  [{_ts()}] [X] 已停止  [=] {tf}文件/{tfl}流/{ta}告警")


def _cmd_pipeline(args) -> None:
    from .config_manager import ConfigManager
    from .triage_pipeline import TriagePipeline
    cfg = ConfigManager()
    inp = args.input or cfg.pipeline.input_dir
    out = args.output or cfg.pipeline.output_dir
    model = args.model or cfg.local_model.model
    max_c = args.max or cfg.pipeline.max_api_calls_per_file

    print(format_separator())
    print(f"  [*] 双层漏斗 v{VERSION}")
    print(f"  [+] Tier1: {model} | Tier2: API LLM")
    print(f"  [+] {inp} -> {out} | 并发: {cfg.local_model.concurrency}")
    print(format_separator())

    pipeline = TriagePipeline(input_dir=inp, output_dir=out, local_model=model,
        local_base_url=cfg.local_model.base_url, local_concurrency=cfg.local_model.concurrency,
        max_api_calls_per_file=max_c)
    asyncio.run(pipeline.run(watch=args.watch, interval=args.interval))


def _cmd_list_experts(_args) -> None:
    experts = [
        ("BeaconDetectorExpert", "C2 Beacon 时序检测", "规律性通信、固定间隔"),
        ("DNSTunnelExpert", "DNS 隧道/外泄检测", "DNS 查询异常大或频繁"),
        ("PortScanExpert", "端口扫描检测", "大量 SYN 到不同端口"),
        ("ICMPTunnelExpert", "ICMP 隐蔽信道检测", "ICMP 载荷 >100B"),
        ("PayloadExpert", "载荷模式分析", "大量上传、固定载荷大小"),
        ("ThreatIntelExpert", "IP/域名威胁情报", "关联已知 APT 组织"),
    ]
    print(f"\n  [+] 可用专家检测模块 ({len(experts)} 个):\n")
    for name, desc, trigger in experts:
        print(f"  - {name}\n    {desc}\n    触发: {trigger}\n")


def _ts(short: bool = False) -> str:
    return datetime.now().strftime("%H:%M:%S" if short else "%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    main()
