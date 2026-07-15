import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

_CONF_KEYS = {
    "backend.provider": ("backend", "provider"),
    "backend.model": ("backend", "model"),
    "backend.api_key": ("backend", "api_key"),
    "backend.base_url": ("backend", "base_url"),
    "analysis.temperature": ("analysis", "temperature"),
    "analysis.max_tokens_dispatch": ("analysis", "max_tokens_dispatch"),
    "analysis.max_tokens_synthesis": ("analysis", "max_tokens_synthesis"),
    "analysis.input_max_chars": ("analysis", "input_max_chars"),
    "daemon.watch_dir": ("daemon", "watch_dir"),
    "daemon.interval": ("daemon", "interval"),
    "daemon.max_per_scan": ("daemon", "max_per_scan"),
    "experts.beacon_detector": ("experts", "beacon_detector"),
    "experts.dns_tunnel": ("experts", "dns_tunnel"),
    "experts.port_scan": ("experts", "port_scan"),
    "experts.icmp_tunnel": ("experts", "icmp_tunnel"),
    "experts.payload_analysis": ("experts", "payload_analysis"),
    "experts.threat_intel": ("experts", "threat_intel"),
    "local_model.base_url": ("local_model", "base_url"),
    "local_model.model": ("local_model", "model"),
    "local_model.concurrency": ("local_model", "concurrency"),
    "pipeline.input_dir": ("pipeline", "input_dir"),
    "pipeline.output_dir": ("pipeline", "output_dir"),
    "pipeline.max_api_calls_per_file": ("pipeline", "max_api_calls_per_file"),
    "logging.level": ("logging", "level"),
    "logging.file_dir": ("logging", "file_dir"),
}


def _default_config_path() -> Path:
    env = os.environ.get("TRAFFIC_ANALYSIS_CONFIG")
    if env:
        return Path(env)
    return Path(__file__).parent.parent.parent / "config.toml"


def _default_defaults() -> dict[str, dict[str, Any]]:
    return {
        "backend": {
            "provider": "deepseek",
            "model": "deepseek-chat",
            "api_key": "",
            "base_url": "",
        },
        "analysis": {
            "temperature": 0.1,
            "max_tokens_dispatch": 300,
            "max_tokens_synthesis": 600,
            "input_max_chars": 3000,
        },
        "daemon": {
            "watch_dir": "./data",
            "interval": 30,
            "max_per_scan": 20,
        },
        "experts": {
            "beacon_detector": True,
            "dns_tunnel": True,
            "port_scan": True,
            "icmp_tunnel": True,
            "payload_analysis": True,
            "threat_intel": True,
        },
        "logging": {
            "level": "INFO",
            "file_dir": "./logs",
        },
    }


def _write_default_config(path: Path) -> dict[str, dict[str, Any]]:
    import textwrap
    content = textwrap.dedent("""\
        # ╔══════════════════════════════════════════════════════════╗
        # ║  流量分析系统 (Traffic Analysis) — 配置文件              ║
        # ║  Config format: TOML (效仿 Claude CLI 配置风格)          ║
        # ╚══════════════════════════════════════════════════════════╝
        #
        # 使用方法:
        #   traffic-analyze config show           查看当前配置
        #   traffic-analyze config set <key> <v>  修改配置项
        #   traffic-analyze config init           重新生成配置文件

        [backend]
        # 后端提供商: deepseek | openai | ollama | lmstudio | custom
        provider = "deepseek"
        model = "deepseek-chat"
        # API Key (也可通过环境变量 LLM_API_KEY 或 DEEPSEEK_API_KEY 覆盖)
        api_key = ""

        [analysis]
        temperature = 0.1
        max_tokens_dispatch = 300
        max_tokens_synthesis = 600
        input_max_chars = 3000

        [daemon]
        watch_dir = "./data"
        interval = 30
        max_per_scan = 20

        [experts]
        beacon_detector = true
        dns_tunnel = true
        port_scan = true
        icmp_tunnel = true
        payload_analysis = true
        threat_intel = true

        [logging]
        level = "INFO"
        file_dir = "./logs"
    """)
    path.write_text(content, encoding="utf-8")
    return _default_defaults()


@dataclass
class BackendConfig:
    provider: str = "deepseek"
    model: str = "deepseek-chat"
    api_key: str = ""
    base_url: str = ""

    _PRESETS = {
        "deepseek": ("DeepSeek", "https://api.deepseek.com/v1"),
        "openai": ("OpenAI", "https://api.openai.com/v1"),
        "ollama": ("Ollama", "http://localhost:11434/v1"),
        "lmstudio": ("LM Studio", "http://localhost:1234/v1"),
    }

    @property
    def display_name(self) -> str:
        return self._PRESETS.get(self.provider, (self.provider,))[0]

    @property
    def resolved_url(self) -> str:
        if self.base_url:
            return self.base_url
        return self._PRESETS.get(self.provider, ("", ""))[1]

    @property
    def is_api_key_required(self) -> bool:
        return self.provider not in ("ollama", "lmstudio")

    @property
    def masked_key(self) -> str:
        if len(self.api_key) <= 8:
            return "***" if self.api_key else "(not set)"
        return self.api_key[:4] + "***" + self.api_key[-4:]


@dataclass
class AnalysisConfig:
    temperature: float = 0.1
    max_tokens_dispatch: int = 300
    max_tokens_synthesis: int = 600
    input_max_chars: int = 3000


@dataclass
class DaemonConfig:
    watch_dir: str = "./data"
    interval: int = 30
    max_per_scan: int = 20


@dataclass
class ExpertsConfig:
    beacon_detector: bool = True
    dns_tunnel: bool = True
    port_scan: bool = True
    icmp_tunnel: bool = True
    payload_analysis: bool = True
    threat_intel: bool = True

    @property
    def enabled_names(self) -> list[str]:
        mapping = {
            "beacon_detector": "BeaconDetectorExpert",
            "dns_tunnel": "DNSTunnelExpert",
            "port_scan": "PortScanExpert",
            "icmp_tunnel": "ICMPTunnelExpert",
            "payload_analysis": "PayloadExpert",
            "threat_intel": "ThreatIntelExpert",
        }
        return [v for k, v in mapping.items() if getattr(self, k)]


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file_dir: str = "./logs"


@dataclass
class LocalModelConfig:
    base_url: str = "http://localhost:11434/v1"
    model: str = "qwen2.5:1.5b"
    concurrency: int = 200


@dataclass
class PipelineConfig:
    input_dir: str = "./input"
    output_dir: str = "./output"
    max_api_calls_per_file: int = 50


class ConfigManager:
    def __init__(self, config_path: Optional[Path] = None):
        self._path = config_path or _default_config_path()
        self.backend = BackendConfig()
        self.analysis = AnalysisConfig()
        self.daemon = DaemonConfig()
        self.experts = ExpertsConfig()
        self.local_model = LocalModelConfig()
        self.pipeline = PipelineConfig()
        self.logging = LoggingConfig()
        self._load()

    @property
    def config_path(self) -> Path:
        return self._path

    def _load(self) -> None:
        if not self._path.exists():
            raw = _write_default_config(self._path)
        else:
            try:
                raw = tomllib.loads(self._path.read_text(encoding="utf-8"))
            except Exception:
                raw = _write_default_config(self._path)

        b = raw.get("backend", {})
        self.backend = BackendConfig(
            provider=b.get("provider", "deepseek"),
            model=b.get("model", "deepseek-chat"),
            api_key=_resolve_api_key(b),
            base_url=b.get("base_url", ""),
        )

        a = raw.get("analysis", {})
        self.analysis = AnalysisConfig(
            temperature=float(a.get("temperature", 0.1)),
            max_tokens_dispatch=int(a.get("max_tokens_dispatch", 300)),
            max_tokens_synthesis=int(a.get("max_tokens_synthesis", 600)),
            input_max_chars=int(a.get("input_max_chars", 3000)),
        )

        d = raw.get("daemon", {})
        self.daemon = DaemonConfig(
            watch_dir=str(d.get("watch_dir", "./data")),
            interval=int(d.get("interval", 30)),
            max_per_scan=int(d.get("max_per_scan", 20)),
        )

        e = raw.get("experts", {})
        self.experts = ExpertsConfig(
            beacon_detector=bool(e.get("beacon_detector", True)),
            dns_tunnel=bool(e.get("dns_tunnel", True)),
            port_scan=bool(e.get("port_scan", True)),
            icmp_tunnel=bool(e.get("icmp_tunnel", True)),
            payload_analysis=bool(e.get("payload_analysis", True)),
            threat_intel=bool(e.get("threat_intel", True)),
        )

        l = raw.get("logging", {})
        self.logging = LoggingConfig(
            level=str(l.get("level", "INFO")),
            file_dir=str(l.get("file_dir", "./logs")),
        )

        lm = raw.get("local_model", {})
        self.local_model = LocalModelConfig(
            base_url=str(lm.get("base_url", "http://localhost:11434/v1")),
            model=str(lm.get("model", "qwen2.5:1.5b")),
            concurrency=int(lm.get("concurrency", 10)),
        )

        pl = raw.get("pipeline", {})
        self.pipeline = PipelineConfig(
            input_dir=str(pl.get("input_dir", "./input")),
            output_dir=str(pl.get("output_dir", "./output")),
            max_api_calls_per_file=int(pl.get("max_api_calls_per_file", 50)),
        )

    def get(self, dotted_key: str) -> Any:
        section, key = _CONF_KEYS[dotted_key]
        section_obj = getattr(self, section)
        return getattr(section_obj, key)

    def set_and_save(self, dotted_key: str, value: str) -> None:
        section, key = _CONF_KEYS[dotted_key]
        section_obj = getattr(self, section)
        current = getattr(section_obj, key)

        # Coerce to original type
        if isinstance(current, bool):
            val = value.lower() in ("true", "1", "yes", "on")
        elif isinstance(current, int):
            val = int(value)
        elif isinstance(current, float):
            val = float(value)
        else:
            val = value

        setattr(section_obj, key, val)
        self._write_toml()

    def _write_toml(self) -> None:
        lines = [
            "# ╔══════════════════════════════════════════════════════════╗",
            "# ║  流量分析系统 (Traffic Analysis) — 配置文件              ║",
            "# ║  Config format: TOML                                     ║",
            "# ╚══════════════════════════════════════════════════════════╝",
            "",
            "[backend]",
            f'provider = "{self.backend.provider}"',
            f'model = "{self.backend.model}"',
        ]
        lines.append(f'api_key = "{self.backend.api_key}"')
        if self.backend.base_url:
            lines.append(f'base_url = "{self.backend.base_url}"')
        else:
            lines.append("# base_url = \"\"")

        lines.extend([
            "",
            "[analysis]",
            f"temperature = {self.analysis.temperature}",
            f"max_tokens_dispatch = {self.analysis.max_tokens_dispatch}",
            f"max_tokens_synthesis = {self.analysis.max_tokens_synthesis}",
            f"input_max_chars = {self.analysis.input_max_chars}",
            "",
            "[daemon]",
            f'watch_dir = "{self.daemon.watch_dir}"',
            f"interval = {self.daemon.interval}",
            f"max_per_scan = {self.daemon.max_per_scan}",
            "",
            "[experts]",
            f"beacon_detector = {str(self.experts.beacon_detector).lower()}",
            f"dns_tunnel = {str(self.experts.dns_tunnel).lower()}",
            f"port_scan = {str(self.experts.port_scan).lower()}",
            f"icmp_tunnel = {str(self.experts.icmp_tunnel).lower()}",
            f"payload_analysis = {str(self.experts.payload_analysis).lower()}",
            f"threat_intel = {str(self.experts.threat_intel).lower()}",
            "",
            "[logging]",
            f'level = "{self.logging.level}"',
            f'file_dir = "{self.logging.file_dir}"',
            "",
            "[local_model]",
            f'base_url = "{self.local_model.base_url}"',
            f'model = "{self.local_model.model}"',
            f"concurrency = {self.local_model.concurrency}",
            "",
            "[pipeline]",
            f'input_dir = "{self.pipeline.input_dir}"',
            f'output_dir = "{self.pipeline.output_dir}"',
            f"max_api_calls_per_file = {self.pipeline.max_api_calls_per_file}",
        ])
        self._path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def show(self) -> str:
        bk = self.backend
        lines = [
            f"  Config file: {self._path}",
            "",
            "  [backend]",
            f"    provider  = {bk.provider}",
            f"    model     = {bk.model}",
            f"    api_key   = {bk.masked_key}",
            f"    base_url  = {bk.resolved_url}",
            "",
            "  [analysis]",
            f"    temperature          = {self.analysis.temperature}",
            f"    max_tokens_dispatch  = {self.analysis.max_tokens_dispatch}",
            f"    max_tokens_synthesis = {self.analysis.max_tokens_synthesis}",
            f"    input_max_chars      = {self.analysis.input_max_chars}",
            "",
            "  [daemon]",
            f"    watch_dir    = {self.daemon.watch_dir}",
            f"    interval     = {self.daemon.interval}s",
            f"    max_per_scan = {self.daemon.max_per_scan}",
            "",
            "  [experts]",
        ]
        for field_name in [
            "beacon_detector", "dns_tunnel", "port_scan",
            "icmp_tunnel", "payload_analysis", "threat_intel",
        ]:
            enabled = getattr(self.experts, field_name)
            icon = "[ON]" if enabled else "[OFF]"
            lines.append(f"    {icon} {field_name}")

        lines.extend([
            "",
            "  [logging]",
            f"    level    = {self.logging.level}",
            f"    file_dir = {self.logging.file_dir}",
            "",
            "  [local_model]",
            f"    base_url    = {self.local_model.base_url}",
            f"    model       = {self.local_model.model}",
            f"    concurrency = {self.local_model.concurrency}",
            "",
            "  [pipeline]",
            f"    input_dir              = {self.pipeline.input_dir}",
            f"    output_dir             = {self.pipeline.output_dir}",
            f"    max_api_calls_per_file = {self.pipeline.max_api_calls_per_file}",
        ])
        return "\n".join(lines)


def _resolve_api_key(backend_raw: dict) -> str:
    key = backend_raw.get("api_key", "")
    if key and key != "sk-***":
        return key

    env_keys = ["LLM_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY"]
    for ek in env_keys:
        env_val = os.environ.get(ek, "")
        if env_val:
            return env_val

    return key
