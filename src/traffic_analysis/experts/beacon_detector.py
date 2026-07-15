import math
from dataclasses import dataclass, field
from typing import Any

from ..constants import (
    BEACON_CONFIDENCE_THRESHOLD,
    BEACON_CV_THRESHOLD_REGULAR,
    BEACON_CV_THRESHOLD_SUSPICIOUS,
    BEACON_DURATION_LONG,
    BEACON_DURATION_SHORT,
    BEACON_REGULARITY_HIGH,
    BEACON_REGULARITY_MEDIUM,
    BEACON_SIZE_CV_THRESHOLD,
    BEACON_SIZE_REGULARITY_HIGH,
    BEACON_SIZE_REGULARITY_MEDIUM,
)

KNOWN_BEACON_PATTERNS: dict[str, dict] = {
    "CobaltStrike_HTTPS": {
        "typical_intervals": [30, 60, 120, 300, 600],
        "typical_sizes": [256, 512, 1024],
        "description": "Cobalt Strike HTTPS Beacon — 固定间隔，加密载荷",
    },
    "Empire_Beacon": {
        "typical_intervals": [5, 10, 15, 30, 60],
        "typical_sizes": [128, 256],
        "description": "PowerShell Empire Beacon — 较短的间隔",
    },
    "Sliver_Beacon": {
        "typical_intervals": [10, 30, 60, 120],
        "typical_sizes": [128, 256, 512, 1024],
        "description": "Sliver C2 Beacon — 灵活间隔",
    },
    "Metasploit_Meterpreter": {
        "typical_intervals": [5, 10, 15],
        "typical_sizes": [128, 256, 512],
        "description": "Metasploit Meterpreter reverse HTTPS",
    },
    "DNS_Beacon": {
        "typical_intervals": [10, 30, 60, 300],
        "typical_sizes": [52, 100, 200, 255],
        "description": "DNS Beacon — 通过DNS查询发送心跳",
    },
}


@dataclass
class BeaconResult:
    is_beacon: bool = False
    confidence: float = 0.0
    matched_pattern: str = ""
    interval: float = 0.0
    interval_regularity: float = 0.0
    packet_size_regularity: float = 0.0
    duration_sec: float = 0.0
    likely_framework: str = ""
    evidence: list[str] = field(default_factory=list)


class BeaconDetectorExpert:
    def __init__(self):
        self.name = "BeaconDetectorExpert"
        self.description = "C2 Beacon 时序检测，识别已知C2框架通信模式"

    def analyze(self, session: dict[str, Any]) -> BeaconResult:
        result = BeaconResult()

        packets: list[dict] = session.get("packets", [])
        if len(packets) < 4:
            return result

        outbound_packets = [p for p in packets if p.get("direction") == "out"]
        if len(outbound_packets) < 3:
            return result

        intervals = self._calc_intervals(outbound_packets)
        if len(intervals) < 2:
            return result

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            return result

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_interval = math.sqrt(variance)
        cv = std_interval / mean_interval

        result.interval = mean_interval
        result.interval_regularity = max(0, 1.0 - min(cv, 2.0) / 2.0)

        if cv < BEACON_CV_THRESHOLD_REGULAR:
            result.evidence.append(f"极规律间隔: CV={cv:.3f} (高度可疑)")
        elif cv < BEACON_CV_THRESHOLD_SUSPICIOUS:
            result.evidence.append(f"比较规律间隔: CV={cv:.3f} (可疑)")

        sizes = [p.get("length", 0) for p in outbound_packets]
        mean_size = sum(sizes) / len(sizes) if sizes else 0.0
        if len(sizes) >= 2 and mean_size > 0:
            size_variance = sum((x - mean_size) ** 2 for x in sizes) / len(sizes)
            size_std = math.sqrt(size_variance)
            size_cv = size_std / mean_size
            result.packet_size_regularity = max(0, 1.0 - min(size_cv, 1.0))
            if size_cv < BEACON_SIZE_CV_THRESHOLD:
                result.evidence.append(
                    f"固定包大小: 均值={mean_size:.0f}B, CV={size_cv:.3f}"
                )

        if outbound_packets:
            result.duration_sec = outbound_packets[-1]["ts"] - outbound_packets[0]["ts"]
        if result.duration_sec > BEACON_DURATION_SHORT * 2:
            result.evidence.append(f"长时间通信: {result.duration_sec:.0f}s")

        score = 0.0

        if result.interval_regularity > BEACON_REGULARITY_HIGH:
            score += 0.5
        elif result.interval_regularity > BEACON_REGULARITY_MEDIUM:
            score += 0.3

        if result.packet_size_regularity > BEACON_SIZE_REGULARITY_HIGH:
            score += 0.3
        elif result.packet_size_regularity > BEACON_SIZE_REGULARITY_MEDIUM:
            score += 0.15

        if result.duration_sec > BEACON_DURATION_SHORT:
            score += 0.1
        if result.duration_sec > BEACON_DURATION_LONG:
            score += 0.1

        best_match, best_score = self._match_framework(mean_interval, mean_size)
        if best_match and best_score > 0.4:
            result.likely_framework = best_match
            result.evidence.append(f"疑似框架: {best_match}")

        result.confidence = min(score, 1.0)
        if result.confidence > BEACON_CONFIDENCE_THRESHOLD:
            result.is_beacon = True

        return result

    @staticmethod
    def _calc_intervals(packets: list[dict]) -> list[float]:
        intervals = []
        for i in range(1, len(packets)):
            diff = packets[i]["ts"] - packets[i - 1]["ts"]
            if diff > 0.5:
                intervals.append(diff)
        return intervals

    @staticmethod
    def _match_framework(mean_interval: float, mean_size: float) -> tuple[str, float]:
        best_match = ""
        best_score = 0.0
        for name, pattern in KNOWN_BEACON_PATTERNS.items():
            match_score = 0.0
            for typical in pattern["typical_intervals"]:
                if abs(mean_interval - typical) < max(5, typical * 0.15):
                    match_score += 0.4
                    break
            for typical in pattern["typical_sizes"]:
                if abs(mean_size - typical) < max(50, typical * 0.2):
                    match_score += 0.3
                    break
            if match_score > best_score:
                best_score = match_score
                best_match = f"{name}: {pattern['description']}"
        return best_match, best_score
