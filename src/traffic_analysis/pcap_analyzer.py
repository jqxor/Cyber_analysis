"""
PCAP/PCAPNG 流量分析器

分析链: tshark (DPI) → 纯Python DPI → 特征提取 → LLM 调度
支持: HTTP/DNS/TLS/TCP 协议深度解析, 流重组, 特征提取
"""

import json
import struct
import socket
import subprocess
import shutil
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


TSHARK = shutil.which("tshark")

try:
    import scapy.all as _scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class FlowFeatures:
    flow_key: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    proto_name: str = ""
    packet_count: int = 0
    duration: float = 0.0
    total_bytes: int = 0
    out_bytes: int = 0
    in_bytes: int = 0
    syn_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    ack_count: int = 0
    # HTTP
    http_methods: list[str] = field(default_factory=list)
    http_hosts: list[str] = field(default_factory=list)
    http_uris: list[str] = field(default_factory=list)
    # DNS
    dns_queries: list[str] = field(default_factory=list)
    dns_types: list[str] = field(default_factory=list)
    # TLS
    tls_snis: list[str] = field(default_factory=list)
    tls_ja3: str = ""
    tls_versions: list[str] = field(default_factory=list)
    # 额外
    app_protocol: str = ""
    suspicious_indicators: list[str] = field(default_factory=list)


def analyze_pcap(filepath: str) -> list[dict[str, Any]]:
    fp = Path(filepath)
    if not fp.exists():
        return []

    if TSHARK:
        sessions = _tshark_analyze(fp)
        if sessions:
            return sessions

    if SCAPY_AVAILABLE:
        sessions = _scapy_analyze(fp)
        if sessions:
            return sessions

    return _python_analyze(fp)



def _tshark_analyze(fp: Path) -> list[dict]:
    try:
        r = subprocess.run(
            [TSHARK, "-r", str(fp), "-T", "json", "-e", "frame.time_epoch",
             "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport",
             "-e", "udp.srcport", "-e", "udp.dstport", "-e", "ip.proto",
             "-e", "frame.len", "-e", "tcp.flags.syn", "-e", "tcp.flags.rst",
             "-e", "tcp.flags.fin", "-e", "tcp.flags.ack",
             "-e", "http.request.method", "-e", "http.host",
             "-e", "http.request.uri", "-e", "http.response.code",
             "-e", "dns.qry.name", "-e", "dns.qry.type",
             "-e", "tls.handshake.extensions_server_name",
             "-e", "tls.handshake.ja3", "-e", "tls.handshake.version",
             "-e", "tcp.analysis.flags",
             "-l"],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            return []
        raw = json.loads(r.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []

    return _json_to_sessions(raw)


def _json_to_sessions(raw: list) -> list[dict]:
    flows: dict[tuple, FlowFeatures] = {}
    packets = []

    for entry in raw:
        layers = entry.get("_source", {}).get("layers", {})
        try:
            ts = float(layers.get("frame.time_epoch", ["0"])[0])
            src = layers.get("ip.src", [""])[0]
            dst = layers.get("ip.dst", [""])[0]
            proto = int(layers.get("ip.proto", ["0"])[0])
            length = int(layers.get("frame.len", ["0"])[0])

            # 端口
            sport = dport = 0
            if proto == 6:  # TCP
                sport = int(layers.get("tcp.srcport", ["0"])[0])
                dport = int(layers.get("tcp.dstport", ["0"])[0])
            elif proto == 17:  # UDP
                sport = int(layers.get("udp.srcport", ["0"])[0])
                dport = int(layers.get("udp.dstport", ["0"])[0])

            key = (src, dst, sport, dport, proto)
            if key not in flows:
                flows[key] = FlowFeatures(
                    flow_key=f"{src}:{sport}->{dst}:{dport}",
                    src_ip=src, dst_ip=dst,
                    src_port=sport, dst_port=dport,
                    protocol=proto,
                )

            f = flows[key]
            f.packet_count += 1
            f.total_bytes += length
            if f.packet_count == 1:
                f.duration = 0
            else:
                f.duration = ts

            syn = layers.get("tcp.flags.syn", ["0"])[0]
            rst = layers.get("tcp.flags.rst", ["0"])[0]
            fin = layers.get("tcp.flags.fin", ["0"])[0]
            ack = layers.get("tcp.flags.ack", ["0"])[0]
            if syn == "1":
                f.syn_count += 1
            if rst == "1":
                f.rst_count += 1
            if fin == "1":
                f.fin_count += 1
            if ack == "1":
                f.ack_count += 1

            # HTTP
            method = layers.get("http.request.method", [""])[0]
            host = layers.get("http.host", [""])[0]
            uri = layers.get("http.request.uri", [""])[0]
            if method:
                f.http_methods.append(method)
                f.app_protocol = "HTTP"
            if host:
                f.http_hosts.append(host)
            if uri:
                f.http_uris.append(uri)

            # DNS
            qname = layers.get("dns.qry.name", [""])[0]
            qtype = layers.get("dns.qry.type", [""])[0]
            if qname:
                f.dns_queries.append(qname)
                f.dns_types.append(qtype)
                f.app_protocol = "DNS"

            # TLS
            sni = layers.get("tls.handshake.extensions_server_name", [""])[0]
            ja3 = layers.get("tls.handshake.ja3", [""])[0]
            tls_v = layers.get("tls.handshake.version", [""])[0]
            if sni:
                f.tls_snis.append(sni)
                f.app_protocol = "TLS"
            if ja3:
                f.tls_ja3 = ja3
            if tls_v:
                f.tls_versions.append(tls_v)

        except (ValueError, KeyError, IndexError):
            continue

    return [_flow_to_session(f) for f in flows.values() if f.packet_count >= 3]



def _scapy_analyze(fp: Path) -> list[dict]:
    try:
        pkts = _scapy.rdpcap(str(fp))
    except Exception:
        return []

    flows: dict[tuple, FlowFeatures] = {}

    for pkt in pkts:
        if not pkt.haslayer("IP"):
            continue
        ip = pkt["IP"]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
        length = len(pkt)
        sport = dport = 0

        if proto == 6 and pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            sport, dport = tcp.sport, tcp.dport
        elif proto == 17 and pkt.haslayer("UDP"):
            udp = pkt["UDP"]
            sport, dport = udp.sport, udp.dport

        key = (src, dst, sport, dport, proto)
        if key not in flows:
            flows[key] = FlowFeatures(
                flow_key=f"{src}:{sport}->{dst}:{dport}",
                src_ip=src, dst_ip=dst,
                src_port=sport, dst_port=dport,
                protocol=proto,
            )
        f = flows[key]
        f.packet_count += 1
        f.total_bytes += length

        if proto == 6:
            tcp_f = pkt["TCP"].flags
            if tcp_f & 0x02:
                f.syn_count += 1
            if tcp_f & 0x04:
                f.rst_count += 1
            if tcp_f & 0x01:
                f.fin_count += 1
            if tcp_f & 0x10:
                f.ack_count += 1

        # HTTP (port 80/8080)
        if (sport in (80, 8080) or dport in (80, 8080)) and pkt.haslayer("Raw"):
            raw = pkt["Raw"].load
            try:
                text = raw.decode("utf-8", errors="replace")
                if text.startswith("GET ") or text.startswith("POST "):
                    f.app_protocol = "HTTP"
                    lines = text.split("\r\n")
                    if lines:
                        parts = lines[0].split()
                        if len(parts) >= 2:
                            f.http_methods.append(parts[0])
                            f.http_uris.append(parts[1])
                    for line in lines:
                        if line.lower().startswith("host:"):
                            f.http_hosts.append(line[5:].strip())
            except Exception:
                pass

        # DNS (port 53)
        if (sport == 53 or dport == 53) and pkt.haslayer("DNS"):
            try:
                dns = pkt["DNS"]
                if dns.qd:
                    f.app_protocol = "DNS"
                    f.dns_queries.append(dns.qd.qname.decode() if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname))
            except Exception:
                pass

        # TLS (port 443)
        if (sport == 443 or dport == 443) and pkt.haslayer("Raw"):
            f.app_protocol = "TLS"

    return [_flow_to_session(f) for f in flows.values() if f.packet_count >= 3]



def _python_analyze(fp: Path) -> list[dict]:
    sessions: dict[tuple, dict] = {}
    try:
        with open(fp, "rb") as f:
            data = f.read()
    except OSError:
        return []

    if len(data) < 24:
        return []

    header = data[:4]
    if header in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        fmt = "<" if header == b"\xd4\xc3\xb2\xa1" else ">"
        offset = 24
    elif header == b"\x0a\x0d\x0d\x0a":
        offset = 28
        fmt = "<"
    else:
        return []

    count = 0
    while offset + 16 <= len(data) and count < 10000:
        try:
            ts_sec = struct.unpack_from(f"{fmt}I", data, offset)[0]
            ts_usec = struct.unpack_from(f"{fmt}I", data, offset + 4)[0]
            incl_len = struct.unpack_from(f"{fmt}I", data, offset + 8)[0]
            if incl_len == 0 or incl_len > 65535:
                break
            pkt_start = offset + 16
            if pkt_start + min(incl_len, 50) > len(data):
                break

            pkt = data[pkt_start:pkt_start + min(incl_len, 200)]
            ts = ts_sec + ts_usec / 1_000_000

            result = _dissect_raw_packet(pkt, incl_len, ts)
            if result:
                key, info = result
                if key not in sessions:
                    sessions[key] = {"start_ts": ts, "end_ts": ts, **info, "count": 0, "total_len": 0,
                                     "flags_set": set(), "http": [], "dns": [], "tls_sni": []}
                s = sessions[key]
                s["end_ts"] = max(s["end_ts"], ts)
                s["total_len"] += incl_len
                s["count"] += 1

            offset = pkt_start + incl_len
            count += 1
        except Exception:
            break

    return [_session_to_report(s) for s in sessions.values() if s["count"] >= 3]


def _dissect_raw_packet(pkt: bytes, length: int, ts: float) -> Optional[tuple]:
    if len(pkt) < 34:
        return None

    ip_off = 14  # 跳过以太网头
    version_ihl = pkt[ip_off]
    ip_version = version_ihl >> 4
    if ip_version not in (4, 6):
        return None

    if ip_version == 4:
        ip_hdr_len = (version_ihl & 0x0F) * 4
        if len(pkt) < ip_off + 20:
            return None
        protocol = pkt[ip_off + 9]
        src = socket.inet_ntoa(pkt[ip_off + 12:ip_off + 16])
        dst = socket.inet_ntoa(pkt[ip_off + 16:ip_off + 20])
    else:
        # IPv6 简单处理
        protocol = pkt[ip_off + 6]
        src = socket.inet_ntop(socket.AF_INET6, pkt[ip_off + 8:ip_off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, pkt[ip_off + 24:ip_off + 40])
        ip_hdr_len = 40

    sport = dport = 0
    transport_off = ip_off + ip_hdr_len

    if protocol in (6, 17) and len(pkt) >= transport_off + 4:
        sport = struct.unpack_from("!H", pkt, transport_off)[0]
        dport = struct.unpack_from("!H", pkt, transport_off + 2)[0]

    flags = 0
    flags_set = set()
    if protocol == 6 and len(pkt) >= transport_off + 14:
        flags = pkt[transport_off + 13]
        flags_set.add(flags)

    # 应用层 DPI
    app_data = b""
    dns_queries = []
    http_info = []
    tls_sni = []
    app_proto = ""

    if protocol == 6:
        tcp_hdr_len = ((pkt[transport_off + 12] >> 4) & 0x0F) * 4
        payload_off = transport_off + tcp_hdr_len
        if len(pkt) > payload_off:
            app_data = pkt[payload_off:]

    elif protocol == 17:
        app_data = pkt[transport_off + 8:] if len(pkt) > transport_off + 8 else b""

    if app_data:
        # HTTP 检测
        if dport in (80, 8080, 8000) or sport in (80, 8080, 8000):
            try:
                text = app_data[:256].decode("ascii", errors="replace")
                if any(text.startswith(m) for m in ("GET ", "POST ", "PUT ", "HEAD ", "HTTP/")):
                    app_proto = "HTTP"
                    http_info.append(text.split("\r\n")[0][:80])
            except Exception:
                pass

        # DNS 检测
        if dport == 53 and len(app_data) > 12:
            try:
                # DNS query name 解析
                qname_parts = []
                pos = 12
                while pos < len(app_data) and app_data[pos] != 0:
                    label_len = app_data[pos]
                    if label_len == 0 or pos + label_len >= len(app_data):
                        break
                    pos += 1
                    qname_parts.append(app_data[pos:pos + label_len].decode("ascii", errors="replace"))
                    pos += label_len
                if qname_parts:
                    qname = ".".join(qname_parts)
                    dns_queries.append(qname)
                    app_proto = "DNS"
            except Exception:
                pass

        # TLS ClientHello 检测
        if app_data[:1] == b"\x16" and len(app_data) >= 6:
            try:
                record_type = app_data[0]
                if record_type == 0x16:  # Handshake
                    hs_type = app_data[5] if len(app_data) > 5 else 0
                    if hs_type == 0x01:  # ClientHello
                        app_proto = "TLS"
                        # 尝试提取 SNI
                        if len(app_data) > 43:
                            # Session ID length at offset 43
                            sid_len = app_data[43]
                            ext_start = 44 + sid_len
                            if len(app_data) > ext_start + 2:
                                ext_total_len = struct.unpack_from("!H", app_data, ext_start)[0]
                                ext_pos = ext_start + 2
                                end = min(ext_pos + ext_total_len, len(app_data))
                                while ext_pos + 4 <= end:
                                    ext_type = struct.unpack_from("!H", app_data, ext_pos)[0]
                                    ext_len = struct.unpack_from("!H", app_data, ext_pos + 2)[0]
                                    if ext_type == 0x0000 and ext_pos + 4 + ext_len <= end:
                                        # SNI extension
                                        sni_data = app_data[ext_pos + 4:ext_pos + 4 + ext_len]
                                        if len(sni_data) > 5:
                                            name_len = struct.unpack_from("!H", sni_data, 3)[0]
                                            sni = sni_data[5:5 + name_len].decode("ascii", errors="replace")
                                            tls_sni.append(sni)
                                        break
                                    ext_pos += 4 + ext_len
            except Exception:
                pass

    key = (src, dst, sport, dport, protocol)
    return key, {
        "src": src, "dst": dst,
        "sport": sport, "dport": dport,
        "protocol": protocol,
        "flags_set": flags_set,
        "app_protocol": app_proto,
        "http": http_info,
        "dns": dns_queries,
        "tls_sni": tls_sni,
    }



def _flow_to_session(f: FlowFeatures) -> dict:
    indicators = list(f.suspicious_indicators)

    if f.app_protocol == "DNS":
        for q in f.dns_queries:
            if len(q) > 50:
                indicators.append(f"DNS长查询: {q[:50]}...")
    if f.syn_count > 50 and f.duration > 0:
        rate = f.syn_count / max(f.duration, 0.01)
        if rate > 10:
            indicators.append(f"SYN flood: {rate:.0f} pps")

    return {
        "scenario": f.flow_key,
        "description": (
            f"{f.app_protocol or 'TCP/UDP'} | {f.packet_count} pkts | {f.total_bytes}B | "
            f"{f.duration:.1f}s"
            + (f" | HTTP: {','.join(f.http_methods[:2])}" if f.http_methods else "")
            + (f" | DNS: {','.join(f.dns_queries[:2])}" if f.dns_queries else "")
            + (f" | TLS: {','.join(f.tls_snis[:2])}" if f.tls_snis else "")
        ),
        "features": {
            "packet_count": f.packet_count,
            "duration_sec": f.duration,
            "total_bytes": f.total_bytes,
            "out_bytes": f.total_bytes // 2,
            "in_bytes": f.total_bytes // 2,
            "upload_ratio": 0.5,
            "unique_ports": 1,
            "port_list": [f.dst_port],
            "beacon_score": _calc_beacon(f),
            "syn_ratio": f.syn_count / max(f.packet_count, 1),
            "rst_ratio": f.rst_count / max(f.packet_count, 1),
            "protocols": [f.protocol],
            "app_protocol": f.app_protocol,
            "indicators": indicators,
        },
        "packets": [
            {
                "ts": 0.0,
                "src": f.src_ip, "dst": f.dst_ip,
                "sport": f.src_port, "dport": f.dst_port,
                "protocol": f.protocol,
                "length": f.total_bytes // max(f.packet_count, 1),
                "flags": 24,
                "direction": "out",
            }
        ],
    }


def _session_to_report(s: dict) -> dict:
    count = s["count"]
    return {
        "scenario": f"{s['src']}:{s['sport']}->{s['dst']}:{s['dport']} [{s['protocol']}]",
        "description": (
            f"{s.get('app_protocol', 'TCP/UDP')} | {count} pkts | {s['total_len']}B | "
            f"{s['end_ts'] - s['start_ts']:.1f}s"
            + (f" | HTTP reqs" if s.get("http") else "")
            + (f" | DNS: {','.join(s.get('dns', [])[:2])}" if s.get("dns") else "")
            + (f" | TLS SNI: {','.join(s.get('tls_sni', [])[:2])}" if s.get("tls_sni") else "")
        ),
        "features": {
            "packet_count": count,
            "duration_sec": s["end_ts"] - s["start_ts"],
            "total_bytes": s["total_len"],
            "out_bytes": s["total_len"] // 2,
            "in_bytes": s["total_len"] // 2,
            "upload_ratio": 0.5,
            "unique_ports": 1,
            "port_list": [s["dport"]],
            "protocols": [s["protocol"]],
        },
        "packets": [
            {
                "ts": s["start_ts"],
                "src": s["src"], "dst": s["dst"],
                "sport": s["sport"], "dport": s["dport"],
                "protocol": s["protocol"],
                "length": s["total_len"] // max(count, 1),
                "flags": 0,
                "direction": "out",
            }
        ],
    }


def _calc_beacon(f: FlowFeatures) -> float:
    if f.packet_count < 5 or f.duration < 10:
        return 0.0
    interval = f.duration / f.packet_count
    if 30 <= interval <= 600:
        return 0.6
    if 10 <= interval <= 30:
        return 0.3
    return 0.0
