
#!/bin/bash
export ZEEK_LOG_DIR="${1:-/usr/local/zeek/logs/current}"
cd "$(dirname "$0")"
uv run python -c "from src.traffic_analysis.zeek_adapter import main; import asyncio; asyncio.run(main())"
