import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from ..constants import (
    DNS_ENTROPY_THRESHOLD,
    DNS_LENGTH_ANOMALOUS,
    DNS_LENGTH_SUSPICIOUS,
    DNS_MIN_QUERIES,
    DNS_CONFIDENCE_THRESHOLD,
    PORT_SCAN_MIN_PACKETS,
    PORT_SCAN_UNIQUE_PORT_THRESHOLD,
    PORT_SCAN_SYN_RATIO_THRESHOLD,
    PORT_SCAN_RATE_THRESHOLD,
    PORT_SCAN_HIT_SERVICES_THRESHOLD,
    PORT_SCAN_SYN_ONLY_RATIO,
    PORT_SCAN_CONFIDENCE_THRESHOLD,
    ICMP_MIN_PACKETS,
    ICMP_PAYLOAD_ANOMALOUS,
    ICMP_PAYLOAD_SUSPICIOUS,
    ICMP_RATE_THRESHOLD,
    ICMP_UNIQUE_SIZES_THRESHOLD,
    ICMP_MIN_PACKETS_FIXED,
    ICMP_CONFIDENCE_THRESHOLD,
    PAYLOAD_MIN_PACKETS,
    PAYLOAD_UPLOAD_RATIO_THRESHOLD,
    PAYLOAD_UPLOAD_BYTES_THRESHOLD,
    PAYLOAD_HTTP_AVG_SIZE,
    PAYLOAD_UNIQUE_SIZE_THRESHOLD,
    PAYLOAD_MIN_PACKETS_FIXED,
    PAYLOAD_CONFIDENCE_THRESHOLD,
)

WELL_KNOWN_SERVICES: dict[int, str] = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
    4444: "Metasploit",
    1337: "Backdoor",
    31337: "BackOrifice",
    6666: "IRC-Bot",
    6667: "IRC",
    8087: "C2-Common",
    9090: "C2-Common",
    9999: "C2-Common",
}

SUSPICIOUS_TLDS: set[str] = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cc", ".pw", ".club", ".work",
}

SUSPICIOUS_HEADERS: list[str] = [
    "POST /api/data",
    "POST /upload",
    "POST /exfil",
    "POST /send",
    "POST /submit",
    "POST /beacon",
    "Content-Type: application/octet-stream",
]


@dataclass
class DNSTunnelResult:
    is_tunnel: bool = False
    confidence: float = 0.0
    avg_query_length: float = 0.0
    avg_entropy: float = 0.0
    unique_queries: int = 0
    query_rate: float = 0.0
    suspicious_tlds: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


class DNSTunnelExpert:
    def __init__(self):
        self.name = "DNSTunnelExpert"
        self.description = "DNS 隧道/外泄检测，分析查询模式"

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        counter = Counter(s)
        length = len(s)
        return -sum(
            (count / length) * math.log2(count / length) for count in counter.values()
        )

    def analyze(self, session: dict[str, Any]) -> DNSTunnelResult:
        result = DNSTunnelResult()
        packets: list[dict] = session.get("packets", [])

        dns_queries = [
            p for p in packets
            if p.get("protocol") == 17
            and (p.get("dport") == 53 or p.get("sport") == 53)
        ]

        if len(dns_queries) < DNS_MIN_QUERIES:
            return result

        lengths = [p.get("length", 0) for p in dns_queries]
        result.avg_query_length = sum(lengths) / len(lengths)

        if result.avg_query_length > DNS_LENGTH_ANOMALOUS:
            result.confidence += 0.4
            result.evidence.append(
                f"DNS查询长度异常: 平均{result.avg_query_length:.0f}字节 (正常<100)"
            )
        elif result.avg_query_length > DNS_LENGTH_SUSPICIOUS:
            result.confidence += 0.2
            result.evidence.append(
                f"DNS查询长度偏大: 平均{result.avg_query_length:.0f}字节"
            )

        length_std = math.sqrt(
            sum((x - result.avg_query_length) ** 2 for x in lengths) / len(lengths)
        )
        result.avg_entropy = min(length_std / max(result.avg_query_length, 1) * 5, 8.0)

        if result.avg_entropy > DNS_ENTROPY_THRESHOLD:
            result.confidence += 0.25
            result.evidence.append(
                f"子域名熵值高: {result.avg_entropy:.1f} (可能包含编码数据)"
            )

        unique_subdomains = len(set(p.get("query", "") for p in dns_queries))
        result.unique_queries = unique_subdomains
        duration = dns_queries[-1]["ts"] - dns_queries[0]["ts"]
        result.query_rate = len(dns_queries) / max(duration, 1)

        if unique_subdomains > 5 and len(dns_queries) > 10:
            result.confidence += 0.2
            result.evidence.append(f"大量唯一子域名查询: {unique_subdomains}个")

        if result.confidence >= DNS_CONFIDENCE_THRESHOLD:
            result.is_tunnel = True

        return result


@dataclass
class PortScanResult:
    is_scan: bool = False
    confidence: float = 0.0
    scan_type: str = ""
    unique_ports: int = 0
    scan_rate: float = 0.0
    ports_hit: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


class PortScanExpert:
    def __init__(self):
        self.name = "PortScanExpert"
        self.description = "端口扫描检测，识别水平/垂直扫描"

    def analyze(self, session: dict[str, Any]) -> PortScanResult:
        result = PortScanResult()
        packets: list[dict] = session.get("packets", [])

        if len(packets) < PORT_SCAN_MIN_PACKETS:
            return result

        dst_ports = [p.get("dport", 0) for p in packets]
        unique_ports = set(dst_ports)
        result.unique_ports = len(unique_ports)

        syn_packets = [p for p in packets if p.get("flags", 0) & 0x02]
        syn_ratio = len(syn_packets) / max(len(packets), 1)

        duration = packets[-1]["ts"] - packets[0]["ts"]
        result.scan_rate = len(packets) / max(duration, 0.01)

        score = 0.0

        if result.unique_ports >= PORT_SCAN_UNIQUE_PORT_THRESHOLD and syn_ratio > PORT_SCAN_SYN_RATIO_THRESHOLD:
            score += 0.5
            result.scan_type = "TCP_SYN_Scan"
            result.evidence.append(f"TCP SYN扫描: {result.unique_ports}个端口")

        if result.scan_rate > PORT_SCAN_RATE_THRESHOLD:
            score += 0.2
            result.evidence.append(f"快速扫描: {result.scan_rate:.1f} ports/s")

        hit_services: list[str] = []
        for port in unique_ports:
            service = WELL_KNOWN_SERVICES.get(port)
            if service:
                hit_services.append(f"{port}({service})")

        if len(hit_services) >= PORT_SCAN_HIT_SERVICES_THRESHOLD:
            result.ports_hit = hit_services
            result.evidence.append(f"扫描关键服务: {', '.join(hit_services[:5])}")
            score += 0.2

        if syn_ratio > PORT_SCAN_SYN_ONLY_RATIO and len(packets) > 10:
            score += 0.1
            result.evidence.append("仅SYN包，无完成三次握手")

        result.confidence = min(score, 1.0)
        if result.confidence >= PORT_SCAN_CONFIDENCE_THRESHOLD:
            result.is_scan = True

        return result


@dataclass
class ICMPTunnelResult:
    is_tunnel: bool = False
    confidence: float = 0.0
    avg_payload_size: float = 0.0
    packet_rate: float = 0.0
    bidirectional: bool = False
    evidence: list[str] = field(default_factory=list)


class ICMPTunnelExpert:
    def __init__(self):
        self.name = "ICMPTunnelExpert"
        self.description = "ICMP 隐蔽信道检测"

    def analyze(self, session: dict[str, Any]) -> ICMPTunnelResult:
        result = ICMPTunnelResult()
        packets: list[dict] = session.get("packets", [])

        icmp_packets = [p for p in packets if p.get("protocol") == 1]
        if len(icmp_packets) < ICMP_MIN_PACKETS:
            return result

        payload_sizes = [p.get("length", 0) for p in icmp_packets]
        result.avg_payload_size = sum(payload_sizes) / len(payload_sizes)

        score = 0.0

        if result.avg_payload_size > ICMP_PAYLOAD_ANOMALOUS:
            score += 0.5
            result.evidence.append(
                f"ICMP载荷异常大: {result.avg_payload_size:.0f}字节 (正常<64)"
            )
        elif result.avg_payload_size > ICMP_PAYLOAD_SUSPICIOUS:
            score += 0.3
            result.evidence.append(
                f"ICMP载荷偏大: {result.avg_payload_size:.0f}字节"
            )

        duration = icmp_packets[-1]["ts"] - icmp_packets[0]["ts"]
        result.packet_rate = len(icmp_packets) / max(duration, 0.01)
        if result.packet_rate > ICMP_RATE_THRESHOLD:
            score += 0.2
            result.evidence.append(f"ICMP高频: {result.packet_rate:.1f} pps")

        unique_sizes = len(set(payload_sizes))
        if unique_sizes <= ICMP_UNIQUE_SIZES_THRESHOLD and len(icmp_packets) >= ICMP_MIN_PACKETS_FIXED:
            score += 0.2
            result.evidence.append(f"ICMP包大小固定: {unique_sizes}种大小")

        result.confidence = min(score, 1.0)
        if result.confidence >= ICMP_CONFIDENCE_THRESHOLD:
            result.is_tunnel = True

        return result


@dataclass
class PayloadResult:
    has_suspicious_pattern: bool = False
    confidence: float = 0.0
    patterns_found: list[str] = field(default_factory=list)
    data_exfil_risk: float = 0.0
    evidence: list[str] = field(default_factory=list)


class PayloadExpert:
    def __init__(self):
        self.name = "PayloadExpert"
        self.description = "载荷模式分析，检测数据外泄和C2通信"

    def analyze(self, session: dict[str, Any]) -> PayloadResult:
        result = PayloadResult()
        packets: list[dict] = session.get("packets", [])

        if len(packets) < PAYLOAD_MIN_PACKETS:
            return result

        score = 0.0

        total_out = sum(
            p.get("length", 0) for p in packets if p.get("direction") == "out"
        )
        total_in = sum(
            p.get("length", 0) for p in packets if p.get("direction") == "in"
        )
        total_traffic = total_out + total_in

        if total_traffic > 0:
            upload_ratio = total_out / total_traffic

            if upload_ratio > PAYLOAD_UPLOAD_RATIO_THRESHOLD and total_out > PAYLOAD_UPLOAD_BYTES_THRESHOLD:
                score += 0.5
                result.data_exfil_risk = upload_ratio
                result.evidence.append(
                    f"大量上传: {total_out} bytes, 占比{upload_ratio:.0%}"
                )

            dst_ports = [p.get("dport", 0) for p in packets]
            if 8080 in dst_ports or 80 in dst_ports:
                out_packets = [p for p in packets if p.get("direction") == "out"]
                out_sizes = [p.get("length", 0) for p in out_packets]
                if out_sizes:
                    avg_out = sum(out_sizes) / len(out_sizes)
                    if avg_out > PAYLOAD_HTTP_AVG_SIZE:
                        score += 0.3
                        result.evidence.append(
                            f"HTTP大量出站: 平均{avg_out:.0f}B/包"
                        )

        sizes = [p.get("length", 0) for p in packets]
        unique_sizes = len(set(sizes))
        if unique_sizes <= PAYLOAD_UNIQUE_SIZE_THRESHOLD and len(packets) >= PAYLOAD_MIN_PACKETS_FIXED:
            score += 0.2
            result.evidence.append(f"载荷大小高度一致: {unique_sizes}种")

        result.confidence = min(score, 1.0)
        if result.confidence > PAYLOAD_CONFIDENCE_THRESHOLD:
            result.has_suspicious_pattern = True

        return result
