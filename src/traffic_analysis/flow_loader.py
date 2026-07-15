import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterator, Optional

from .constants import (
    BRUTEFORCE_PORTS,
    SUSPICIOUS_PORTS,
    IDS_BEACON_DURATION_LONG,
    IDS_BEACON_PKT_STD_LOW,
    IDS_BEACON_PKT_STD_VLOW,
    IDS_BEACON_SCORE_DEFAULT,
    IDS_BEACON_SCORE_HIGH,
    IDS_AGGREGATION_WINDOW_THRESHOLD,
)


def _safe_float(value: Any, default: float = 0.0) -> float:
    if value is None or value == "" or str(value) in ("Infinity", "NaN", "-Infinity"):
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def parse_flow_row(row: dict[str, str]) -> Optional[dict[str, Any]]:
    try:
        src_ip = (row.get("Src IP") or row.get(" Source IP") or "0.0.0.0").strip()
        dst_ip = (row.get("Dst IP") or row.get(" Destination IP") or "0.0.0.0").strip()
        protocol = int(_safe_float(row.get("Protocol")))
        src_port = int(_safe_float(row.get("Src Port") or row.get(" Source Port")))
        dst_port = int(_safe_float(row.get("Dst Port") or row.get(" Destination Port")))
        timestamp = (row.get("Timestamp") or "").strip()

        fwd_pkts = int(_safe_float(row.get("Tot Fwd Pkts") or row.get("Total Fwd Packets")))
        bwd_pkts = int(_safe_float(row.get("Tot Bwd Pkts") or row.get("Total Backward Packets")))
        fwd_bytes = int(_safe_float(row.get("TotLen Fwd Pkts") or row.get("Total Length of Fwd Packets")))
        bwd_bytes = int(_safe_float(row.get("TotLen Bwd Pkts") or row.get("Total Length of Bwd Packets")))
        duration = _safe_float(row.get("Flow Duration")) / 1_000_000

        syn_count = int(_safe_float(row.get("SYN Flag Cnt") or row.get("SYN Flag Count")))
        fin_count = int(_safe_float(row.get("FIN Flag Cnt") or row.get("FIN Flag Count")))
        rst_count = int(_safe_float(row.get("RST Flag Cnt") or row.get("RST Flag Count")))
        psh_count = int(_safe_float(row.get("PSH Flag Cnt") or row.get("PSH Flag Count")))
        ack_count = int(_safe_float(row.get("ACK Flag Cnt") or row.get("ACK Flag Count")))

        avg_len = _safe_float(row.get("Pkt Size Avg") or row.get("Average Packet Size"))
        len_std = _safe_float(row.get("Pkt Len Std") or row.get("Packet Length Std"))
        flow_bytes_sec = _safe_float(row.get("Flow Byts/s") or row.get("Flow Bytes/s"))
        flow_pkts_sec = _safe_float(row.get("Flow Pkts/s") or row.get("Flow Packets/s"))

        label = (row.get("Label") or "").strip()

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "timestamp": timestamp,
            "duration": duration,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "fwd_pkts": fwd_pkts,
            "bwd_pkts": bwd_pkts,
            "syn_count": syn_count,
            "fin_count": fin_count,
            "rst_count": rst_count,
            "psh_count": psh_count,
            "ack_count": ack_count,
            "avg_pkt_len": avg_len,
            "pkt_len_std": len_std,
            "flow_bytes_sec": flow_bytes_sec,
            "flow_pkts_sec": flow_pkts_sec,
            "_label": label,
        }
    except (ValueError, KeyError, TypeError):
        return None


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


def flow_to_session(flow: dict[str, Any]) -> dict[str, Any]:
    total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]
    total_pkts = flow["fwd_pkts"] + flow["bwd_pkts"]

    if flow["fwd_pkts"] > 1 and flow["duration"] > 0:
        interval = flow["duration"] / flow["fwd_pkts"]
        beacon_score = 0.0
        if 30 <= interval <= 600 and flow["pkt_len_std"] < IDS_BEACON_PKT_STD_LOW:
            beacon_score = IDS_BEACON_SCORE_DEFAULT
            if flow["pkt_len_std"] < IDS_BEACON_PKT_STD_VLOW:
                beacon_score = IDS_BEACON_SCORE_HIGH
    else:
        interval = 0.0
        beacon_score = 0.0

    upload_ratio = flow["fwd_bytes"] / max(total_bytes, 1)
    syn_ratio = flow["syn_count"] / max(total_pkts, 1) if total_pkts > 0 else 0.0

    return {
        "flow_key": (
            f"{flow.get('src_ip', '?')}:{flow['src_port']}→"
            f"{flow.get('dst_ip', '?')}:{flow['dst_port']}"
        ),
        "description": (
            f"Flow: {flow['fwd_pkts']}fwd/{flow['bwd_pkts']}bwd pkts, "
            f"{total_bytes}B, {flow['duration']:.2f}s"
        ),
        "risk_score": 0.0,
        "_label": flow["_label"],
        "features": {
            "packet_count": total_pkts,
            "duration_sec": flow["duration"],
            "total_bytes": total_bytes,
            "out_bytes": flow["fwd_bytes"],
            "in_bytes": flow["bwd_bytes"],
            "upload_ratio": upload_ratio,
            "beacon_score": beacon_score,
            "interval_mean": interval,
            "interval_std": flow["pkt_len_std"],
            "packet_size_mean": flow["avg_pkt_len"],
            "packet_size_std": flow["pkt_len_std"],
            "syn_ratio": syn_ratio,
            "rst_ratio": flow["rst_count"] / max(total_pkts, 1),
            "unique_ports": 1,
            "protocols": [flow["protocol"]],
        },
        "packets": [
            {
                "ts": 0.0,
                "src": flow.get("src_ip", "?"),
                "dst": flow.get("dst_ip", "?"),
                "sport": flow["src_port"],
                "dport": flow["dst_port"],
                "protocol": flow["protocol"],
                "length": flow["avg_pkt_len"],
                "flags": ((2 if flow["syn_count"] > 0 else 0) | (16 if flow["ack_count"] > 0 else 0)),
                "direction": "out",
            }
        ],
    }


class FlowLoader:
    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.total_flows = 0
        self.filtered_flows = 0
        self.labels_seen: dict[str, int] = defaultdict(int)

    def load_all(self) -> list[dict[str, Any]]:
        sessions = []
        for flow in self.iter_flows():
            sessions.append(flow_to_session(flow))
        return sessions

    def iter_flows(self) -> Iterator[dict[str, Any]]:
        with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
            bom = f.read(1)
            if bom != "\ufeff":
                f.seek(0)

            reader = csv.DictReader(f)
            for row in reader:
                self.total_flows += 1
                flow = parse_flow_row(row)
                if flow is not None:
                    self.labels_seen[flow["_label"]] += 1
                    yield flow

    def filter_suspicious(self, min_score: float = 0.1) -> Iterator[dict[str, Any]]:
        all_flows = list(self.iter_flows())
        self.total_flows = len(all_flows)

        window_flows: dict[tuple[int, int], list[int]] = defaultdict(list)
        yielded: set[int] = set()

        for idx, flow in enumerate(all_flows):
            score = self._score_flow(flow, window_flows, all_flows, idx)
            if score >= min_score:
                self.filtered_flows += 1
                yielded.add(idx)
                yield flow

        self._yield_aggregated(all_flows, window_flows, yielded)

    def _score_flow(
        self,
        flow: dict[str, Any],
        window_flows: dict[tuple[int, int], list[int]],
        all_flows: list,
        idx: int,
    ) -> float:
        score = 0.0

        ts_str = flow["timestamp"]
        window = 0
        try:
            parts = ts_str.split()
            if len(parts) >= 2:
                h, m, s = parts[1].split(":")
                window = int(h) * 3600 + int(m) * 60 + (int(s) // 30) * 30
        except (ValueError, IndexError):
            pass

        port_key = flow["dst_port"]
        window_flows[(port_key, window)].append(idx)

        if flow["dst_port"] in BRUTEFORCE_PORTS and flow["protocol"] == 6:
            if flow["syn_count"] > 0:
                score += 0.2

        if flow["dst_port"] in SUSPICIOUS_PORTS:
            score += 0.4

        total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]
        if total_bytes > 0 and flow["fwd_bytes"] / total_bytes > 0.85 and flow["fwd_bytes"] > 10000:
            score += 0.3

        if flow["protocol"] == 1 and flow["avg_pkt_len"] > 100:
            score += 0.5

        if (
            flow["duration"] > IDS_BEACON_DURATION_LONG
            and flow["pkt_len_std"] < IDS_BEACON_PKT_STD_LOW
            and flow["fwd_pkts"] > 10
        ):
            score += 0.3

        return score

    def _yield_aggregated(
        self,
        all_flows: list,
        window_flows: dict[tuple[int, int], list[int]],
        yielded: set[int],
    ):
        for (port, window), indices in window_flows.items():
            if len(indices) < IDS_AGGREGATION_WINDOW_THRESHOLD:
                continue
            for idx in indices:
                if idx in yielded:
                    continue
                flows = [all_flows[i] for i in indices]
                agg = dict(all_flows[idx])
                agg["fwd_pkts"] = sum(f["fwd_pkts"] for f in flows)
                agg["syn_count"] = sum(f["syn_count"] for f in flows)
                agg["fwd_bytes"] = sum(f["fwd_bytes"] for f in flows)
                labels = [f["_label"] for f in flows if f["_label"]]
                agg["_label"] = Counter(labels).most_common(1)[0][0] if labels else ""
                agg["_aggregated"] = len(indices)
                self.filtered_flows += 1
                yielded.add(idx)
                yield agg
                break

    def get_label_distribution(self) -> dict[str, int]:
        return dict(self.labels_seen)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_flows": self.total_flows,
            "filtered_flows": self.filtered_flows,
            "filter_rate": 1 - (self.filtered_flows / max(self.total_flows, 1)),
            "labels": dict(self.labels_seen),
        }
