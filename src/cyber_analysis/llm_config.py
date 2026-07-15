import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

PRESET_BACKENDS: dict[str, tuple] = {
    "deepseek": ("DeepSeek", "https://api.deepseek.com/v1", "deepseek-chat", "DEEPSEEK_API_KEY"),
    "openai": ("OpenAI", "https://api.openai.com/v1", "gpt-3.5-turbo", "OPENAI_API_KEY"),
    "ollama": ("Ollama", "http://localhost:11434/v1", "qwen3:1.7b", None),
    "lmstudio": ("LM Studio", "http://localhost:1234/v1", "auto", None),
}

DEFAULT_DISPATCH_TOKENS = 300
DEFAULT_SYNTHESIS_TOKENS = 600
LOCAL_DISPATCH_TOKENS = 200
LOCAL_SYNTHESIS_TOKENS = 400
DEFAULT_INPUT_CHARS = 3000
LOCAL_INPUT_CHARS = 2500


@dataclass
class LLMBackend:
    name: str
    base_url: str
    api_key: str = ""
    model: str = "auto"
    max_tokens_dispatch: int = DEFAULT_DISPATCH_TOKENS
    max_tokens_synthesis: int = DEFAULT_SYNTHESIS_TOKENS
    temperature: float = 0.1
    input_max_chars: int = DEFAULT_INPUT_CHARS

    @property
    def is_available(self) -> bool:
        if not self.api_key and self.name not in ("ollama", "lmstudio"):
            return False
        return True

    @property
    def masked_key(self) -> str:
        if len(self.api_key) <= 8:
            return "***"
        return self.api_key[:4] + "***" + self.api_key[-4:]

    def __repr__(self) -> str:
        return (
            f"LLMBackend(name={self.name!r}, model={self.model!r}, "
            f"key={self.masked_key}, url={self.base_url})"
        )


def _make_backend(key: str) -> LLMBackend:
    name, url, model, env_key = PRESET_BACKENDS[key]
    api_key = ""
    if env_key:
        api_key = os.environ.get(env_key, "")

    is_local = key in ("ollama", "lmstudio")
    if is_local:
        api_key = key

    backend = LLMBackend(name=name, base_url=url, model=model, api_key=api_key)
    if is_local:
        backend.max_tokens_dispatch = LOCAL_DISPATCH_TOKENS
        backend.max_tokens_synthesis = LOCAL_SYNTHESIS_TOKENS
        backend.input_max_chars = LOCAL_INPUT_CHARS
    return backend


class Config:
    """LLM 配置 — 加载优先级: config.toml > 环境变量 > config.json (兼容旧版)"""

    def __init__(self):
        self.backend: Optional[LLMBackend] = None
        self._load_dotenv()
        self._load()

    @property
    def _project_root(self) -> Path:
        return Path(__file__).parent.parent.parent

    @property
    def legacy_config_file(self) -> Path:
        return self._project_root / "config.json"

    @property
    def toml_config_file(self) -> Path:
        return self._project_root / "config.toml"

    @property
    def env_file(self) -> Path:
        return self._project_root / ".env"

    def _load_dotenv(self) -> None:
        if not self.env_file.exists():
            return
        for line in self.env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k not in os.environ:
                os.environ[k] = v

    def _load(self) -> None:
        # 1) config.toml (preferred)
        if self.toml_config_file.exists():
            if self._try_load_toml():
                return

        # 2) 环境变量
        if self._try_load_env():
            return

        # 3) 旧版 config.json
        if self._try_load_legacy_json():
            return

        # 4) 自动检测本地 LLM
        self.auto_detect()

    def _try_load_toml(self) -> bool:
        try:
            from .config_manager import ConfigManager
            cm = ConfigManager(self.toml_config_file)
            bk = cm.backend
            backend = _make_backend(bk.provider)

            # Override from TOML
            if bk.model:
                backend.model = bk.model
            if bk.api_key:
                backend.api_key = bk.api_key
            backend.temperature = cm.analysis.temperature
            backend.max_tokens_dispatch = cm.analysis.max_tokens_dispatch
            backend.max_tokens_synthesis = cm.analysis.max_tokens_synthesis
            backend.input_max_chars = cm.analysis.input_max_chars

            self.backend = backend
            return self.backend.is_available
        except Exception:
            return False

    def _try_load_env(self) -> bool:
        backend_name = os.environ.get("LLM_BACKEND", "").lower()
        custom_url = os.environ.get("LLM_BASE_URL", "")
        custom_key = os.environ.get("LLM_API_KEY", "")
        custom_model = os.environ.get("LLM_MODEL", "auto")

        if backend_name and backend_name in PRESET_BACKENDS:
            self.backend = _make_backend(backend_name)
            if custom_key:
                self.backend.api_key = custom_key
            if custom_url:
                self.backend.base_url = custom_url
            if custom_model != "auto":
                self.backend.model = custom_model
            return self.backend.is_available

        if custom_url:
            self.backend = LLMBackend(
                name="custom",
                base_url=custom_url,
                api_key=custom_key or "na",
                model=custom_model,
            )
            return True

        return False

    def _try_load_legacy_json(self) -> bool:
        if not self.legacy_config_file.exists():
            return False
        try:
            data = json.loads(self.legacy_config_file.read_text(encoding="utf-8"))
            bn = data.get("backend", data.get("name", "")).lower()
            if bn in PRESET_BACKENDS:
                self.backend = _make_backend(bn)
                if data.get("api_key"):
                    self.backend.api_key = data["api_key"]
                if data.get("base_url"):
                    self.backend.base_url = data["base_url"]
                if data.get("model"):
                    self.backend.model = data["model"]
                return self.backend.is_available
            if data.get("base_url"):
                self.backend = LLMBackend(
                    name=data.get("name", "custom"),
                    base_url=data["base_url"],
                    api_key=data.get("api_key", "na"),
                    model=data.get("model", "auto"),
                )
                return True
        except (json.JSONDecodeError, KeyError):
            pass
        return False

    def auto_detect(self) -> Optional[LLMBackend]:
        import httpx

        for port in (1234, 1235):
            try:
                r = httpx.get(f"http://localhost:{port}/v1/models", timeout=1.5)
                if r.status_code == 200:
                    self.backend = _make_backend("lmstudio")
                    self.backend.base_url = f"http://localhost:{port}/v1"
                    return self.backend
            except Exception:
                continue

        try:
            r = httpx.get("http://localhost:11434/api/tags", timeout=1.5)
            if r.status_code == 200:
                self.backend = _make_backend("ollama")
                return self.backend
        except Exception:
            pass

        return None

    def set_backend(self, name: str, **overrides) -> None:
        if name in PRESET_BACKENDS:
            self.backend = _make_backend(name)
        else:
            self.backend = LLMBackend(
                name=name,
                base_url=overrides.get("base_url", ""),
                api_key=overrides.get("api_key", ""),
                model=overrides.get("model", "auto"),
            )
        for k, v in overrides.items():
            if hasattr(self.backend, k):
                setattr(self.backend, k, v)

    def save(self) -> None:
        if self.backend is None:
            return
        data = {
            "name": self.backend.name,
            "base_url": self.backend.base_url,
            "api_key": self.backend.api_key if self.backend.name == "custom" else "",
            "model": self.backend.model,
        }
        self.legacy_config_file.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    @property
    def is_ready(self) -> bool:
        return self.backend is not None and self.backend.is_available
