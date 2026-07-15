<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/LLM-双模型协作-FF6B35?logo=openai&logoColor=white" alt="LLM"/>
  <img src="https://img.shields.io/badge/Ollama-本地推理-000000?logo=ollama&logoColor=white" alt="Ollama"/>
  <img src="https://img.shields.io/badge/PCAP-深度解析-34A853" alt="PCAP"/>
  <img src="https://img.shields.io/badge/MIT-License-blue" alt="License"/>
</p>

<h1 align="center">Cyber Analysis</h1>

<p align="center">
  <b>AI驱动的网络流量分析器</b> — 大小模型双层漏斗架构，本地小 LLM 初筛 + API 大 LLM 深析
</p>

---

## 架构

```
流量数据 (CSV/JSON/PCAP)
    │
    ▼
┌──────────────────────────────────────┐
│        Tier 1: 本地小 LLM             │
│  并行初筛，过滤 ~80% 误报              │
├──────────────────────────────────────┤
│        Tier 2: API 大 LLM             │
│  提供DeepSeek / OpenAI / 自定义等接口  │
│  调度 6 专家 → 综合报告 → ATT&CK+IOC   │
└──────────────────────────────────────┘
```

核心原则：

- **Tier 1** 本地零成本过滤，只把真正可疑的流量上报
- **Tier 2** 大模型理解上下文，6 专家并行检测后统一研判
- **管道** 输入目录 → 初筛 → 深析 → 输出目录，全自动闭环

---

## 功能特性

- **双层漏斗** — 小模型 +  LLM大模型 深析
- **6 大检测专家** — Beacon / DNS 隧道 / 端口扫描 / ICMP 信道 / 载荷外泄 / 威胁情报
- **多格式支持** — CSV  / JSON (自定义场景) / PCAP
- **配置即用** — 单个 `config.toml` 管理所有参数，`traffic-analyze config set` 一键修改
- **守护模式** — `--watch` 持续监控目录，新文件到达自动分析
- **本地 AI** — 按显存自由选择模型

---

## 6 大专家模块

| 专家 | 检测能力 | 触发条件 |
|------|---------|---------|
| BeaconDetector | C2 Beacon 时序检测 | 固定间隔通信 |
| DNSTunnel | DNS 隧道 / 数据外泄 | 查询异常长、高熵值 |
| PortScan | 端口扫描检测 | 大量 SYN 到多端口 |
| ICMPTunnel | ICMP 隐蔽信道 | 载荷 > 100B |
| Payload | 载荷模式分析 | 大量上传、固定大小 |
| ThreatIntel | IP/域名威胁情报 | 命中已知恶意 IOC |

---

## 快速开始

```shell
# 1. 克隆
git clone https://github.com/jqxor/Cyber_analysis.git
cd Cyber_analysis

# 2. 安装依赖
uv sync

# 3. 配置
cp config.toml.example config.toml
traffic-analyze config set backend.api_key sk-your-key

# 4. (可选) 启动本地 Ollama
ollama pull qwen2.5:1.5b

# 5. 分析
traffic-analyze scan data.csv --max 30
```

## 配置

```toml
[backend]
provider = "deepseek"          # 根据实际模型调用进行修改
model    = "deepseek-chat"
api_key  = ""                  # 你的 Key

[local_model]
model       = "your_model"     # 本地模型
concurrency = 200              # Tier 1 并发数

[pipeline]
input_dir              = "./input"
output_dir             = "./output"
max_api_calls_per_file = 50  # 单次并发最大读取文件数
```

---

## CLI 命令

```shell 
traffic-analyze scan <path>                 # 自动识别文件/目录/格式
traffic-analyze analyze-ids <csv> --max 50  # 标签对比
traffic-analyze pipeline --watch            # 管道持续监控
traffic-analyze daemon --watch ./data       # 文件守护
traffic-analyze config show                 # 查看当前配置
traffic-analyze list-experts                # 专家模块列表
```

---

## 项目结构

```
Cyber_analysis/
├── config.toml.example         # 配置模板
├── pyproject.toml              # 项目 & CLI 入口
├── traffic-analyze.bat         # Windows 快捷入口
├── main.py / daemon.py         # 旧版入口 (兼容)
└── src/traffic_analysis/
    ├── cli.py                  # CLI 主入口 (6 子命令)
    ├── orchestrator.py         # 大小模型调度器
    ├── triage_pipeline.py      # Tier1 → Tier2 漏斗
    ├── config_manager.py       # TOML 配置管理
    ├── pcap_analyzer.py        # PCAP 三层分析 (tshark/scapy/Python)
    ├── flow_loader.py          # CSV/IDS 加载
    ├── feature_extractor.py    # 特征工程
    └── experts/
        ├── analyzers.py        # DNS/PortScan/ICMP/Payload
        ├── beacon_detector.py  # C2 Beacon
        ├── threat_intel.py     # 威胁情报
        └── local_expert.py     # Ollama 本地专家
```

---

## PCAP 分析链路

```
PCAP 文件
    │  tshark (Wireshark DPI)     ← 优先
    │  scapy (Python DPI)         ← 备选
    │  Python (HTTP/DNS/TLS)      ← 兜底
    ▼
流重组 → 特征提取 → Tier 1 初筛 → Tier 2 深析 → 报告
```

---

## 许可

MIT License © 2025
