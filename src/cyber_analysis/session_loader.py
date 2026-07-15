import json
import time
from pathlib import Path
from typing import Any

from .feature_extractor import extract_features, classify_direction


def load_json_sessions(filepath: str) -> list[dict[str, Any]]:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    base_ts = data.get("timestamp_base", time.time())
    sessions = []

    for scenario in data["scenarios"]:
        packets = scenario["packets"]

        enriched = []
        for p in packets:
            enriched.append({
                "ts": base_ts + p["ts"],
                "src": p["src"],
                "dst": p["dst"],
                "sport": p["sport"],
                "dport": p["dport"],
                "protocol": p["proto"],
                "length": p["len"],
                "flags": p["flags"],
                "direction": classify_direction(p["src"]),
            })

        features = extract_features(enriched)

        sessions.append({
            "scenario": scenario["name"],
            "description": scenario["description"],
            "packets": enriched,
            "features": features,
            "risk_score": 0.0,
        })

    return sessions


def load_json_sessions_daemon(fp: Path) -> list[dict[str, Any]]:
    data = json.loads(fp.read_text(encoding="utf-8"))
    sessions = []

    for scenario in data.get("scenarios", []):
        packets = scenario["packets"]
        for p in packets:
            p.setdefault("direction", "out")
            p.setdefault("ts", p.get("ts", 0))
            if "proto" in p and "protocol" not in p:
                p["protocol"] = p["proto"]
            if "len" in p and "length" not in p:
                p["length"] = p["len"]
            if "flags" not in p:
                p["flags"] = 0

        features = extract_features(packets)
        sessions.append({
            "scenario": scenario["name"],
            "description": scenario.get("description", ""),
            "packets": packets,
            "features": features,
            "risk_score": 0.0,
        })

    return sessions
