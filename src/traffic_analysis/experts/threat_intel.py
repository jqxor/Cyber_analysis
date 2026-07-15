from dataclasses import dataclass, field
from typing import Any, Optional

KNOWN_MALICIOUS_IPS: dict[str, dict[str, Any]] = {
    "185.213.189.103": {"score": 0.95, "tags": ["CobaltStrike", "C2", "APT29"], "first_seen": "2024-01"},
    "41.95.171.248": {"score": 0.90, "tags": ["DataExfil", "ICMP_Tunnel", "Lazarus"], "first_seen": "2024-03"},
    "29.53.186.35": {"score": 0.85, "tags": ["HTTP_C2", "Exfiltration", "APT41"], "first_seen": "2024-06"},
    "65.19.163.254": {"score": 0.70, "tags": ["Suspicious", "Proxy"], "first_seen": "2024-08"},
    "16.143.80.199": {"score": 0.65, "tags": ["Scanner", "Reconnaissance"], "first_seen": "2024-09"},
    "12.24.156.125": {"score": 0.60, "tags": ["Suspicious", "Scanner"], "first_seen": "2024-10"},
    "50.212.244.72": {"score": 0.55, "tags": ["Suspicious", "Unusual_Traffic"], "first_seen": "2024-11"},
    "35.91.137.79": {"score": 0.50, "tags": ["AWS_Suspicious", "Potential_Scanner"], "first_seen": "2025-01"},
}

KNOWN_MALICIOUS_DOMAINS: dict[str, dict[str, Any]] = {
    "evil.com": {"score": 0.95, "tags": ["C2", "Phishing"]},
    "attacker.evil.com": {"score": 0.98, "tags": ["C2", "DataExfil"]},
    "malware.c2server.net": {"score": 0.92, "tags": ["C2", "Trojan"]},
    "exfil.data-stealer.top": {"score": 0.88, "tags": ["DataExfil"]},
}

PRIVATE_IP_PREFIXES = ("192.168.", "10.", "172.")


def _ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


_SUSPICIOUS_RANGES = [
    ("185.213.189.0", "185.213.189.255", "Known_C2_Hosting"),
    ("41.95.171.0", "41.95.171.255", "Known_Exfil_Hosting"),
    ("29.53.186.0", "29.53.186.255", "Suspicious_Hosting"),
]

SUSPICIOUS_RANGES: list[tuple[int, int, str]] = [
    (_ip_to_int(start), _ip_to_int(end), label)
    for start, end, label in _SUSPICIOUS_RANGES
]


def _is_private_ip(ip: str) -> bool:
    return ip.startswith(PRIVATE_IP_PREFIXES)


def _extract_external_ips(packets: list[dict]) -> list[str]:
    ips: list[str] = []
    for p in packets:
        dst = p.get("dst", "")
        if not isinstance(dst, str) or "." not in dst:
            continue
        parts = dst.split(".")
        if len(parts) != 4:
            continue
        if not all(part.replace("-", "").isdigit() for part in parts):
            continue
        if not _is_private_ip(dst):
            ips.append(dst)
    return list(set(ips))


@dataclass
class ThreatIntelResult:
    query: str = ""
    is_known_malicious: bool = False
    confidence: float = 0.0
    tags: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    recommended_action: str = "monitor"


class ThreatIntelExpert:
    def __init__(self):
        self.name = "ThreatIntelExpert"
        self.description = "IP/域名信誉查询，关联已知APT组织"

    def check_ip(self, ip: str) -> ThreatIntelResult:
        result = ThreatIntelResult(query=ip)

        if ip in KNOWN_MALICIOUS_IPS:
            intel = KNOWN_MALICIOUS_IPS[ip]
            result.is_known_malicious = True
            result.confidence = intel["score"]
            result.tags = list(intel["tags"])
            result.matched_rules.append(
                f"known_malicious_ip: {', '.join(intel['tags'])}"
            )
            result.recommended_action = "block_ip"
            return result

        ip_int = _ip_to_int(ip)
        for start, end, label in SUSPICIOUS_RANGES:
            if start <= ip_int <= end:
                result.confidence = max(result.confidence, 0.6)
                result.tags.append(label)
                result.matched_rules.append(f"suspicious_range: {label}")
                result.is_known_malicious = True
                break

        return result

    def check_domain(self, domain: str) -> ThreatIntelResult:
        result = ThreatIntelResult(query=domain)

        if domain in KNOWN_MALICIOUS_DOMAINS:
            intel = KNOWN_MALICIOUS_DOMAINS[domain]
            result.is_known_malicious = True
            result.confidence = intel["score"]
            result.tags = list(intel["tags"])
            result.matched_rules.append(
                f"known_malicious_domain: {', '.join(intel['tags'])}"
            )
            result.recommended_action = "block_domain"

        return result

    def analyze(self, session: dict[str, Any]) -> ThreatIntelResult:
        ips = _extract_external_ips(session.get("packets", []))
        if ips:
            return self.check_ip(ips[0])
        return ThreatIntelResult(query=session.get("scenario", session.get("flow_key", "?")))

    def analyze_batch(
        self,
        ips: Optional[list[str]] = None,
        domains: Optional[list[str]] = None,
        session: Optional[dict[str, Any]] = None,
    ) -> list[ThreatIntelResult]:
        results: list[ThreatIntelResult] = []

        if session and not ips:
            ips = _extract_external_ips(session.get("packets", []))

        for ip in ips or []:
            results.append(self.check_ip(ip))

        for domain in domains or []:
            results.append(self.check_domain(domain))

        return results
