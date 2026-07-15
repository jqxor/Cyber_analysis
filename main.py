import asyncio
import os
import sys
import time
from pathlib import Path

from src.traffic_analysis.logger import setup_file_logging, get_logger
from src.traffic_analysis.llm_config import Config
from src.traffic_analysis.orchestrator import LLMOrchestrator
from src.traffic_analysis.session_loader import load_json_sessions
from src.traffic_analysis.report_formatter import format_report_console, format_separator

logger = get_logger(__name__)


async def main() -> None:
    default_file = Path(__file__).parent / "tests" / "test_traffic.json"

    if "--file" in sys.argv:
        idx = sys.argv.index("--file")
        filepath = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else str(default_file)
    else:
        filepath = str(default_file)

    if not os.path.exists(filepath):
        logger.error("文件不存在: %s", filepath)
        print(format_separator())
        print("  用法: uv run python main.py [--file <path>]")
        print(format_separator())
        return

    setup_file_logging(Path(__file__).parent / "logs")

    print(format_separator())
    print("  🔬 流量分析系统 — 大模型调度小模型")
    print(f"  📂 数据文件: {filepath}")
    print(format_separator())

    sessions = load_json_sessions(filepath)
    logger.info("加载 %d 个场景", len(sessions))
    print(f"\n  📦 加载 {len(sessions)} 个场景\n")

    config = Config()
    if not config.is_ready:
        config.auto_detect()

    if not config.is_ready:
        print("  ❌ 未找到可用的 LLM 后端\n")
        try:
            key = input("  🔑 输入 DeepSeek API Key (直接回车跳过): ").strip()
            if key:
                config.set_backend("deepseek", api_key=key)
                config.save()
                print("  ✅ 已保存到 config.json")
        except (EOFError, KeyboardInterrupt):
            pass

        if not config.is_ready:
            print("\n  配置方法:")
            print("    DeepSeek:  export LLM_BACKEND=deepseek  LLM_API_KEY=sk-...")
            print("    Ollama:    export LLM_BACKEND=ollama")
            print("    或创建 .env 文件写入: LLM_BACKEND=deepseek")
            return

    backend = config.backend
    logger.info("使用后端: %s | %s", backend.name, backend.model)
    print(f"  🤖 后端: {backend.name} | 模型: {backend.model}")
    print(f"  📡 {backend.base_url}\n")

    orchestrator = LLMOrchestrator(config)

    stats = {"total": 0, "malicious": 0, "benign": 0}

    for i, session in enumerate(sessions):
        scenario_name = session.get("scenario", f"Session {i}")
        logger.info("分析场景 [%d/%d]: %s", i + 1, len(sessions), scenario_name)
        print(f"  [场景 {i+1}/{len(sessions)}] 分析中...")

        start = time.time()
        try:
            report = await orchestrator.analyze(session)
        except Exception:
            logger.exception("场景分析失败: %s", scenario_name)
            continue
        elapsed = time.time() - start

        print(format_report_console(report, session))
        print(f"     ⏱️  耗时: {elapsed:.2f}s\n")

        stats["total"] += 1
        if report.is_malicious:
            stats["malicious"] += 1
        else:
            stats["benign"] += 1

    print(format_separator())
    print(f"  📊 分析总结")
    print(f"     总场景: {stats['total']}")
    print(f"     恶意: {stats['malicious']}")
    print(f"     正常: {stats['benign']}")
    print(format_separator())


if __name__ == "__main__":
    asyncio.run(main())
