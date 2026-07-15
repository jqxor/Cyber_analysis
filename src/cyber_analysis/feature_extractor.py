import math
from typing import Any

from .constants import SUBNET_RANGES, BEACON_MIN_INTERVALS, BEACON_DURATION_SHORT


def is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    return False


def classify_direction(src: str) -> str:
    if src.startswith(("192.168", "10.", "172.")):
        return "out"
    return "in"


def extract_features(packets: list[dict[str, Any]]) -> dict[str, Any]:
    if not packets:
        return {}

    n = len(packets)
    duration = packets[-1]["ts"] - packets[0]["ts"]

    protocols = set(p["protocol"] for p in packets)
    dst_ports = [p["dport"] for p in packets]
    unique_ports = len(set(dst_ports))

    out_pkts = [p for p in packets if p.get("direction", "out") == "out"]
    in_pkts = [p for p in packets if p.get("direction", "out") == "in"]
    out_bytes = sum(p["length"] for p in out_pkts)
    in_bytes = sum(p["length"] for p in in_pkts)
    total_bytes = out_bytes + in_bytes

    out_times = [p["ts"] for p in out_pkts]
    intervals = [
        out_times[i] - out_times[i - 1]
        for i in range(1, len(out_times))
    ]

    beacon_score = 0.0
    interval_mean = 0.0
    interval_std = 0.0
    if len(intervals) >= BEACON_MIN_INTERVALS:
        interval_mean = sum(intervals) / len(intervals)
        if interval_mean > 0:
            variance = sum((x - interval_mean) ** 2 for x in intervals) / len(intervals)
            interval_std = math.sqrt(variance)
            cv = interval_std / interval_mean
            beacon_score = max(0, 1.0 - min(cv, 2.0) / 2.0)
            if duration > BEACON_DURATION_SHORT:
                beacon_score = min(1.0, beacon_score + 0.2)

    sizes = [p["length"] for p in packets]
    size_mean = sum(sizes) / n
    size_std = math.sqrt(sum((x - size_mean) ** 2 for x in sizes) / n)

    syn_count = sum(1 for p in packets if p.get("flags", 0) & 0x02)
    rst_count = sum(1 for p in packets if p.get("flags", 0) & 0x04)

    return {
        "packet_count": n,
        "duration_sec": duration,
        "total_bytes": total_bytes,
        "out_bytes": out_bytes,
        "in_bytes": in_bytes,
        "upload_ratio": out_bytes / max(total_bytes, 1),
        "unique_ports": unique_ports,
        "port_list": sorted(set(dst_ports))[:10],
        "beacon_score": beacon_score,
        "interval_mean": interval_mean,
        "interval_std": interval_std,
        "packet_size_mean": size_mean,
        "packet_size_std": size_std,
        "syn_ratio": syn_count / max(n, 1),
        "rst_ratio": rst_count / max(n, 1),
        "protocols": list(protocols),
    }


def extract_features_basic(packets: list[dict[str, Any]]) -> dict[str, Any]:
    if not packets:
        return {}
    n = len(packets)
    duration = packets[-1]["ts"] - packets[0]["ts"]
    lengths = [p.get("len", p.get("length", 0)) for p in packets]
    avg_len = sum(lengths) / n
    return {
        "packet_count": n,
        "duration_sec": duration,
        "total_bytes": sum(lengths),
        "packet_size_mean": avg_len,
        "packet_size_std": math.sqrt(
            sum((x - avg_len) ** 2 for x in lengths) / n
        ),
    }
