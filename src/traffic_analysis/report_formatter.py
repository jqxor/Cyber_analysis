from typing import Any

_REPORT_SEP = "═" * 68
_REPORT_SEP_THIN = "─" * 68

THREAT_ICONS = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
    "None": "⚪",
}


def format_separator(thin: bool = False) -> str:
    return _REPORT_SEP_THIN if thin else _REPORT_SEP


def _fmt_verdict(report) -> str:
    icon = THREAT_ICONS.get(report.threat_level, "⚪")
    lines = [f"\n  {icon} 最终判定:"]
    lines.append(f"     恶意: {'⚠️ 是' if report.is_malicious else '✅ 否'}")
    lines.append(f"     类型: {report.attack_type}")
    lines.append(f"     等级: {report.threat_level}")
    lines.append(f"     置信度: {report.confidence:.0%}")
    if report.attck_techniques:
        lines.append(f"     ATT&CK: {', '.join(report.attck_techniques)}")
    if report.iocs.get("ips") or report.iocs.get("domains"):
        lines.append(f"     IOC: {report.iocs}")
    if report.recommendations:
        lines.append(f"     建议: {', '.join(report.recommendations)}")
    return "\n".join(lines)


def format_report_console(report, scenario: dict[str, Any]) -> str:
    lines = [
        format_separator(),
        f"  📋 {scenario['scenario']}",
        f"  📝 {scenario['description']}",
        format_separator(thin=True),
    ]

    if report.dispatch_reasoning:
        lines.append(f"\n  🧠 LLM 调度决策:")
        lines.append(f"     {report.dispatch_reasoning}")

    if report.expert_findings:
        lines.append(f"\n  🔬 专家小模型分析:")
        for name, result in report.expert_findings.items():
            if hasattr(result, "__dict__"):
                d = result.__dict__
                key_fields = []
                field_mapping = [
                    ("is_beacon", "Beacon"),
                    ("is_tunnel", "Tunnel"),
                    ("is_scan", "Scan"),
                    ("is_known_malicious", "恶意"),
                    ("has_suspicious_pattern", "可疑"),
                ]
                for key, label in field_mapping:
                    if key in d:
                        key_fields.append(f"{label}={'是' if d[key] else '否'}")
                if "confidence" in d:
                    key_fields.append(f"置信度={d['confidence']:.0%}")
                evidence = d.get("evidence", [])
                lines.append(f"     [{name}] {', '.join(key_fields)}")
                for ev in evidence[:3]:
                    lines.append(f"       └ {ev}")
            else:
                lines.append(f"     [{name}] {result}")

    lines.append(_fmt_verdict(report))
    lines.append(format_separator())
    lines.append("")
    return "\n".join(lines)


def format_zeek_finding(report, ev) -> str:
    icon = THREAT_ICONS.get(report.threat_level, "⚪")
    return (
        f"  {icon} [{report.threat_level}] "
        f"{ev.conn.orig_h}→{ev.conn.resp_h}:{ev.conn.resp_p} "
        f"| {report.attack_type} | {report.confidence:.0%}"
    )
