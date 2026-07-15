# Cyber Analysis

千万级网络流量分析系统 — **大模型调度小模型** 双层漏斗架构

## 架构

```
流量数据 (CSV/JSON/PCAP)
    │
    ▼
┌─────────────────────┐
│  Tier 1: 本地小 LLM  │  Ollama (qwen2.5:1.5b)
│  并行初筛，过滤误报    │  ~200ms/条，过滤 ~80%
└──────────┬──────────┘
           │ 可疑流
           ▼
┌─────────────────────┐
│  Tier 2: API 大 LLM  │  DeepSeek / OpenAI
│  调度6专家 + 综合报告  │  完整 ATT&CK + IOC
└──────────┬──────────┘
           │
           ▼
       报告输出 (JSON)
```

## 快速开始

```bash
# 1. 安装依赖
uv sync

# 2. 初始化配置
cp config.toml.example config.toml
traffic-analyze config set backend.api_key sk-your-key

# 3. (可选) 启动 Ollama 本地模型
ollama pull qwen2.5:1.5b

# 4. 使用
traffic-analyze scan data.csv --max 30
traffic-analyze pipeline --input ./input --output ./output
```

## CLI 命令

```bash
traffic-analyze scan <path>              # 自动识别文件/目录/格式
traffic-analyze analyze-ids <csv>        # IDS2018 带标签验证
traffic-analyze pipeline                 # 双层漏斗管道
traffic-analyze daemon --watch ./data    # 文件监控守护
traffic-analyze config show              # 查看配置
traffic-analyze list-experts             # 专家模块列表
```

## 配置文件

复制模板后修改:

```bash
cp config.toml.example config.toml
```

关键配置项:

```toml
[backend]
provider = "deepseek"          # deepseek | openai | ollama | lmstudio | custom
model = "deepseek-chat"
api_key = ""                   # 你的 API Key

[local_model]
model = "qwen2.5:1.5b"         # Ollama 本地模型
concurrency = 200              # 并发数

[pipeline]
input_dir = "./input"
output_dir = "./output"
max_api_calls_per_file = 50    # 管控成本
```

## 6 大专家检测模块

| 专家 | 检测能力 | 触发条件 |
|------|---------|---------|
| BeaconDetector | C2 Beacon 时序检测 | 固定间隔心跳 |
| DNSTunnel | DNS 隧道/外泄 | 查询异常长/高熵 |
| PortScan | 端口扫描 | 大量 SYN 到多端口 |
| ICMPTunnel | ICMP 隐蔽信道 | 载荷 >100B |
| Payload | 载荷/外泄分析 | 大量上传 |
| ThreatIntel | IP/域名情报 | 匹配已知恶意 IOC |

## 多格式支持

| 格式 | 分析链路 | 协议解析 |
|------|---------|---------|
| CSV | FlowLoader → LLM | IDS2018 格式 |
| JSON | SessionLoader → LLM | 自定义场景 |
| PCAP | tshark/scapy/Python → LLM | HTTP/DNS/TLS 深度解析 |

## 依赖

- Python >= 3.12
- [uv](https://docs.astral.sh/uv/) 包管理器
- [Ollama](https://ollama.com) (可选，本地 Tier 1)

## 安全

- **不要提交** `config.toml`、`.env` 到仓库
- API Key 日志输出自动脱敏
- 使用 `config.toml.example` 作为模板

## License

MIT
