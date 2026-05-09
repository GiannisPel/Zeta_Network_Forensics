import json

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether, Dot1Q
from scapy.layers.dns import DNS

try:
    from scapy.layers.l2 import STP
except Exception:  # scapy builds differ
    STP = None

try:
    from scapy.layers.dhcp import BOOTP, DHCP
except Exception:  # scapy builds differ
    BOOTP = None
    DHCP = None

from embedder import get_model
from ml_anomaly import load_model, extract_features, predict
from flow_tracker import FlowTracker
from l2_tracker import ARPTracker, DHCPTracker, MACFloodTracker, STPTracker, VLANTracker
from app import net_db, get_net_index, flush_net_index
import app as _app
import numpy as np

#Packets embedded and inserted per batch.
#Keeps RAM flatter on small containers regardless of capture size.
BATCH_SIZE = 256


def _safe_mac_from_bootp_chaddr(chaddr) -> str:
    try:
        if isinstance(chaddr, bytes):
            raw = chaddr[:6]
            return ":".join(f"{b:02x}" for b in raw)
        return str(chaddr).lower()
    except Exception:
        return ""


def _dhcp_message_type_name(value) -> str:
    mapping = {
        1: "DISCOVER",
        2: "OFFER",
        3: "REQUEST",
        4: "DECLINE",
        5: "ACK",
        6: "NAK",
        7: "RELEASE",
        8: "INFORM",
    }
    if isinstance(value, int):
        return mapping.get(value, str(value))
    return str(value).upper()


def _extract_vlan_ids(pkt) -> list[int]:
    
    #Extract VLAN IDs robustly from Scapy-decoded Dot1Q/Dot1AD layers and, if Scapy does not decode stacked tags cleanly, from raw Ethernet bytes.

    #This is required for VLAN-hopping captures where Scapy exposes only Ether.type=0x8100 but not the nested Dot1Q objects.
    
    vlan_ids: list[int] = []

    # Path A: Scapy layer traversal.
    layer = pkt
    guard = 0
    while layer is not None and guard < 16:
        guard += 1
        if layer.__class__.__name__ in {"Dot1Q", "Dot1AD"}:
            try:
                vlan_ids.append(int(layer.vlan))
            except Exception:
                pass
        payload = getattr(layer, "payload", None)
        if payload is None or payload is layer or payload.__class__.__name__ == "NoPayload":
            break
        layer = payload

    #Path B: raw Ethernet fallback.
    #Ethernet header: dst(6) src(6) ethertype(2).
    #VLAN tag: TPID(2) TCI(2); VLAN ID = TCI & 0x0FFF.
    try:
        raw = bytes(pkt)
        if len(raw) >= 18:
            offset = 12
            guard = 0
            raw_ids: list[int] = []
            while len(raw) >= offset + 4 and guard < 4:
                guard += 1
                tpid = int.from_bytes(raw[offset:offset + 2], "big")
                if tpid not in {0x8100, 0x88A8, 0x9100}:
                    break
                tci = int.from_bytes(raw[offset + 2:offset + 4], "big")
                raw_ids.append(tci & 0x0FFF)
                offset += 4
            if len(raw_ids) > len(vlan_ids):
                vlan_ids = raw_ids
    except Exception:
        pass

    return vlan_ids


def _parse_stp_fields(pkt) -> dict:
    if STP is None or STP not in pkt:
        return {}
    stp = pkt[STP]
    out = {"protocol": "STP"}
    #Scapy STP field names differ by version, so read defensively.
    for name in ("rootid", "rootmac", "bridgeid", "bridgemac", "portid", "age", "maxage", "hellotime", "fwddelay"):
        try:
            out[name] = getattr(stp, name)
        except Exception:
            pass

    try:
        out["root_id"] = f"{getattr(stp, 'rootid', '')}:{getattr(stp, 'rootmac', '')}"
    except Exception:
        out["root_id"] = str(out.get("rootid", ""))
    try:
        out["bridge_id"] = f"{getattr(stp, 'bridgeid', '')}:{getattr(stp, 'bridgemac', '')}"
    except Exception:
        out["bridge_id"] = str(out.get("bridgeid", ""))

    #STP priority is the high bits of the bridge/root id in many encodings. If cannot extract it, leave None
    root_priority = None
    try:
        root_priority = int(getattr(stp, "rootid"))
    except Exception:
        pass
    out["root_priority"] = root_priority
    return out


def _parse_packet(pkt, index: int) -> dict | None:
    
    #Extract all relevant layers from a Scapy packet into a meta dict and returns None if the packet has no supported network/L2 layer
    meta = {
        "layers": {
            "l2": {},
            "network": {},
            "transport": {},
            "application": {},
        },
        "packet": {},
    }

    total_size = len(pkt)
    meta["packet"]["timestamp"] = float(pkt.time)
    meta["packet"]["bytes"] = total_size
    meta["packet"]["packet_index"] = index
    meta["packet"]["header_size"] = 0

    if Ether in pkt:
        eth = pkt[Ether]
        _vlan_ids = _extract_vlan_ids(pkt)
        meta["layers"]["l2"] = {
            "eth_src": str(eth.src).lower(),
            "eth_dst": str(eth.dst).lower(),
            "eth_type": int(eth.type) if getattr(eth, "type", None) is not None else None,
            "vlan_ids": _vlan_ids,
            "vlan_tags": _vlan_ids,  # alias for SQL/debug compatibility
        }

    #Layer 2 / ARP branch.
    if ARP in pkt:
        arp = pkt[ARP]
        meta["layers"]["network"] = {
            "type": "ARP",
            "src_ip": arp.psrc,
            "dst_ip": arp.pdst,
            "protocol_number": 0,
            "ttl": 0,
            "is_fragment": False,
        }
        meta["layers"]["transport"] = {
            "protocol": "ARP",
            "src_port": 0,
            "dst_port": 0,
            "tcp_flags": 0,
        }
        meta["layers"]["application"] = {
            "protocol": "ARP",
            "op": int(arp.op),
            "psrc": arp.psrc,
            "pdst": arp.pdst,
            "hwsrc": str(arp.hwsrc).lower(),
            "hwdst": str(arp.hwdst).lower(),
        }
        meta["packet"]["header_size"] = 28

    elif STP is not None and STP in pkt:
        stp_info = _parse_stp_fields(pkt)
        meta["layers"]["network"] = {
            "type": "STP",
            "src_ip": meta["layers"]["l2"].get("eth_src"),
            "dst_ip": meta["layers"]["l2"].get("eth_dst"),
            "protocol_number": 0,
            "ttl": 0,
            "is_fragment": False,
        }
        meta["layers"]["transport"] = {
            "protocol": "STP",
            "src_port": 0,
            "dst_port": 0,
            "tcp_flags": 0,
        }
        meta["layers"]["application"] = stp_info
        meta["packet"]["header_size"] = 35

    elif IP in pkt:
        ip = pkt[IP]
        meta["layers"]["network"] = {
            "type": "IPv4",
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "protocol_number": ip.proto,
            "ttl": ip.ttl,
            "is_fragment": bool(ip.flags & 0x1),  #MF flag
        }
        meta["packet"]["header_size"] = ip.ihl * 4

    elif IPv6 in pkt:
        ip = pkt[IPv6]
        meta["layers"]["network"] = {
            "type": "IPv6",
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "protocol_number": ip.nh,
            "ttl": ip.hlim,
            "is_fragment": False,
        }
        meta["packet"]["header_size"] = 40

    elif Ether in pkt:
        #Ethernet-only frames are still useful for MAC flood / VLAN behavior
        meta["layers"]["network"] = {
            "type": "Ethernet",
            "src_ip": meta["layers"]["l2"].get("eth_src"),
            "dst_ip": meta["layers"]["l2"].get("eth_dst"),
            "protocol_number": 0,
            "ttl": 0,
            "is_fragment": False,
        }
        meta["layers"]["transport"] = {
            "protocol": "ETHERNET",
            "src_port": 0,
            "dst_port": 0,
            "tcp_flags": 0,
        }
        meta["layers"]["application"] = {"protocol": "ETHERNET"}

    else:
        return None

    #Transport layer
    if TCP in pkt:
        tcp = pkt[TCP]
        meta["layers"]["transport"] = {
            "protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "tcp_flags": int(tcp.flags),
        }
        meta["packet"]["header_size"] += tcp.dataofs * 4

    elif UDP in pkt:
        udp = pkt[UDP]
        meta["layers"]["transport"] = {
            "protocol": "UDP",
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "tcp_flags": 0,
        }
        meta["packet"]["header_size"] += 8

    elif ICMP in pkt:
        icmp = pkt[ICMP]
        meta["layers"]["transport"] = {
            "protocol": "ICMP",
            "icmp_type": icmp.type,
            "icmp_code": icmp.code,
            "tcp_flags": 0,
        }
        meta["packet"]["header_size"] += 4
    # DHCP/BOOTP over UDP. Checked before DNS because it also lives at app layer
    if BOOTP is not None and DHCP is not None and BOOTP in pkt and DHCP in pkt:
        bootp = pkt[BOOTP]
        dhcp = pkt[DHCP]
        dhcp_info = {
            "protocol": "DHCP",
            "xid": int(getattr(bootp, "xid", 0) or 0),
            "ciaddr": str(getattr(bootp, "ciaddr", "") or ""),
            "yiaddr": str(getattr(bootp, "yiaddr", "") or ""),
            "siaddr": str(getattr(bootp, "siaddr", "") or ""),
            "giaddr": str(getattr(bootp, "giaddr", "") or ""),
            "chaddr": _safe_mac_from_bootp_chaddr(getattr(bootp, "chaddr", b"")),
            "client_mac": meta["layers"].get("l2", {}).get("eth_src", ""),
        }
        try:
            for opt in dhcp.options:
                if not isinstance(opt, tuple) or len(opt) < 2:
                    continue
                k, v = opt[0], opt[1]
                if k == "message-type":
                    dhcp_info["message_type"] = _dhcp_message_type_name(v)
                elif k == "requested_addr":
                    dhcp_info["requested_addr"] = str(v)
                elif k == "hostname":
                    try:
                        dhcp_info["hostname"] = v.decode(errors="ignore") if isinstance(v, bytes) else str(v)
                    except Exception:
                        pass
        except Exception:
            pass
        meta["layers"]["application"] = dhcp_info

    #DNS runs over UDP/TCP and is checked independently.
    elif DNS in pkt:
        dns = pkt[DNS]
        app_info = {
            "protocol": "DNS",
            "is_response": bool(dns.qr),
            "answer_count": int(dns.ancount) if hasattr(dns, "ancount") else 0,
            "query_length": 0,
        }
        if dns.qd:
            try:
                qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
                app_info["query"] = qname
                app_info["query_length"] = len(qname)
            except Exception:
                pass
        meta["layers"]["application"] = app_info

    #VLAN evidence should remain in l2 even if IP/DHCP/DNS is present
    if meta["layers"].get("l2", {}).get("vlan_ids"):
        meta["layers"]["l2"]["vlan_tag_count"] = len(meta["layers"]["l2"]["vlan_ids"])
        meta["layers"]["l2"]["double_tagged"] = len(meta["layers"]["l2"]["vlan_ids"]) >= 2
        meta["layers"]["l2"]["outer_vlan"] = meta["layers"]["l2"]["vlan_ids"][0]
        meta["layers"]["l2"]["inner_vlan"] = meta["layers"]["l2"]["vlan_ids"][1] if len(meta["layers"]["l2"]["vlan_ids"]) >= 2 else None

    return meta


def _build_embed_text(meta: dict) -> str:
    net = meta["layers"]["network"]
    transport = meta["layers"]["transport"]
    app = meta["layers"]["application"]
    l2 = meta["layers"].get("l2", {})

    src_ip = net.get("src_ip")
    dst_ip = net.get("dst_ip")
    proto = transport.get("protocol", "N/A")
    src_port = transport.get("src_port")
    dst_port = transport.get("dst_port")
    flags = transport.get("tcp_flags", 0)
    app_proto = app.get("protocol", "")
    dns_query = app.get("query", "")

    if app_proto == "ARP":
        return (
            f"ARP op={app.get('op')} {src_ip}({app.get('hwsrc', '?')}) → "
            f"{dst_ip}({app.get('hwdst', '?')}) psrc={app.get('psrc')} pdst={app.get('pdst')}"
        )
    if app_proto == "DHCP":
        return (
            f"DHCP {app.get('message_type','UNKNOWN')} "
            f"client={app.get('client_mac') or app.get('chaddr')} "
            f"xid={app.get('xid')} requested={app.get('requested_addr','')}"
        )
    if app_proto == "STP":
        return (
            f"STP BPDU root={app.get('root_id','?')} bridge={app.get('bridge_id','?')} "
            f"eth={l2.get('eth_src')}→{l2.get('eth_dst')}"
        )

    if l2.get("vlan_ids"):
        vlan_desc = " vlan=" + "/".join(str(v) for v in l2.get("vlan_ids", []))
    else:
        vlan_desc = ""

    parts = [f"{src_ip}:{src_port} → {dst_ip}:{dst_port} [{proto}]{vlan_desc}"]

    if flags:
        flag_names = []
        if flags & 0x02:
            flag_names.append("SYN")
        if flags & 0x10:
            flag_names.append("ACK")
        if flags & 0x04:
            flag_names.append("RST")
        if flags & 0x01:
            flag_names.append("FIN")
        if flags & 0x08:
            flag_names.append("PSH")
        if flag_names:
            parts.append(f"flags={'+'.join(flag_names)}")

    if app_proto:
        parts.append(app_proto)
    if dns_query:
        parts.append(f"query={dns_query}")

    return " ".join(parts)


def _fallback_ml() -> dict:
    return {
        "anomaly": False,
        "score": 0.0,
        "reasons": [],
        "attack_type": "ANOMALOUS_TRAFFIC",
        "confidence": 0.0,
        "severity": "LOW",
        "trained": False,
    }


def _score_packet(model, meta: dict, flow_stats: dict) -> None:
    """Score a normal packet/l2_packet. Packet rows must not use flow-summary promotion."""
    try:
        features = extract_features(meta, flow_stats)
        meta["ml"] = predict(
            model,
            features,
            meta=meta,
            flow_stats=flow_stats,
            is_flow_summary=False,
        )
    except Exception:
        meta["ml"] = _fallback_ml()


def _score_summary(model, rep_meta: dict, final_stats: dict) -> None:
    """Score flow_summary/l2_summary rows with summary promotion enabled."""
    try:
        features = extract_features(rep_meta, final_stats)
        rep_meta["ml"] = predict(
            model,
            features,
            meta=rep_meta,
            flow_stats=final_stats,
            is_flow_summary=True,
        )
    except Exception:
        rep_meta["ml"] = _fallback_ml()


def _l2_summary_records(trackers: list, model):
    
    #Yield (record_id_suffix, text, meta, timestamp) for completed L2 summaries.
    
    seq = 0
    for tracker in trackers:
        for l2_key, l2_stats in tracker.finalize_all():
            rep_meta = l2_stats.get("last_meta")
            if rep_meta is None:
                continue

            rep_meta = dict(rep_meta)
            final_stats = dict(l2_stats)
            final_stats.pop("last_meta", None)

            rep_meta["flow"] = final_stats
            rep_meta["flow_record_type"] = "l2_summary"

            _score_summary(model, rep_meta, final_stats)

            proto = final_stats.get("l2_protocol", l2_key[0] if isinstance(l2_key, tuple) else "L2")
            if proto == "ARP":
                text = (
                    f"L2 ARP SUMMARY mac={final_stats.get('arp_hwsrc', '?')} "
                    f"claimed_ips={final_stats.get('mac_claimed_ips', [])} "
                    f"replies={final_stats.get('arp_reply_count', 0)} "
                    f"gratuitous={final_stats.get('gratuitous_arp_count', 0)} "
                    f"targets={final_stats.get('target_ips', [])}"
                )
            elif proto == "DHCP":
                text = (
                    f"L2 DHCP SUMMARY messages={final_stats.get('dhcp_total_messages', 0)} "
                    f"unique_client_macs={final_stats.get('dhcp_unique_client_macs', 0)} "
                    f"discovers={final_stats.get('dhcp_discover_count', 0)} "
                    f"requests={final_stats.get('dhcp_request_count', 0)}"
                )
            elif proto == "ETHERNET":
                text = (
                    f"L2 MAC SUMMARY unique_src_macs={final_stats.get('mac_flood_unique_src_macs', 0)} "
                    f"frames={final_stats.get('mac_flood_total_frames', 0)} "
                    f"burst_5s={final_stats.get('mac_flood_burst_5s', 0)}"
                )
            elif proto == "STP":
                text = (
                    f"L2 STP SUMMARY bpdus={final_stats.get('stp_bpdu_count', 0)} "
                    f"unique_roots={final_stats.get('stp_unique_root_ids', 0)} "
                    f"min_root_priority={final_stats.get('stp_min_root_priority')}"
                )
            elif proto == "VLAN":
                text = (
                    f"L2 VLAN SUMMARY double_tagged={final_stats.get('vlan_double_tagged_count', 0)} "
                    f"outer={final_stats.get('vlan_outer_ids', {})} "
                    f"inner={final_stats.get('vlan_inner_ids', {})}"
                )
            else:
                text = f"L2 SUMMARY protocol={proto} stats={final_stats}"

            yield f"l2:{seq}", text, rep_meta, rep_meta["packet"]["timestamp"]
            seq += 1


def ingest_pcap_file(path: str, capture_id: str) -> int:
    
    #Parse a PCAP/PCAPNG and store packet, flow_summary, and l2_summary records.
    packets = rdpcap(path)
    model = load_model()
    tracker = FlowTracker()
    arp_tracker = ARPTracker()
    dhcp_tracker = DHCPTracker()
    mac_tracker = MACFloodTracker()
    stp_tracker = STPTracker()
    vlan_tracker = VLANTracker()
    l2_trackers = [arp_tracker, dhcp_tracker, mac_tracker, stp_tracker, vlan_tracker]
    embed_model = get_model()

    idx = get_net_index(dim=384)
    conn = net_db()
    cur = conn.cursor()

    batch_texts = []
    batch_metas = []
    batch_ids = []
    batch_ts = []
    added = 0

    def flush_batch():
        nonlocal added
        if not batch_texts:
            return

        vecs = embed_model.encode(
            batch_texts,
            normalize_embeddings=True,
            batch_size=BATCH_SIZE,
            show_progress_bar=False,
        )
        vecs = np.asarray(vecs, dtype=np.float32)

        start_row = int(idx.ntotal)
        idx.add(vecs)

        rows = [
            (
                batch_ids[j],
                capture_id,
                batch_texts[j],
                batch_ts[j],
                json.dumps(batch_metas[j], ensure_ascii=False),
                start_row + j,
            )
            for j in range(len(batch_texts))
        ]

        cur.executemany(
            """
            INSERT OR IGNORE INTO net_memories
            (id, capture_id, text, created_at, meta_json, faiss_row)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
        added += len(rows)

        batch_texts.clear()
        batch_metas.clear()
        batch_ids.clear()
        batch_ts.clear()

    #Pass 1: packet/l2_packet scoring.
    for i, pkt in enumerate(packets):
        meta = _parse_packet(pkt, i)
        if meta is None:
            continue

        # Always update passive L2 trackers. They decide later whether behavior is analyzable.
        mac_tracker.update(meta)
        vlan_tracker.update(meta)

        app_proto = meta.get("layers", {}).get("application", {}).get("protocol")
        net_type = meta.get("layers", {}).get("network", {}).get("type")

        if app_proto == "ARP":
            flow_stats = arp_tracker.update(meta)
            meta["flow_record_type"] = "l2_packet"
        elif app_proto == "DHCP":
            flow_stats = dhcp_tracker.update(meta)
            meta["flow_record_type"] = "l2_packet"
        elif app_proto == "STP" or net_type in {"STP", "Ethernet"}:
            if app_proto == "STP":
                flow_stats = stp_tracker.update(meta)
            else:
                flow_stats = {}
            meta["flow_record_type"] = "l2_packet"
        else:
            flow_stats = tracker.update(meta)
            meta["flow_record_type"] = "packet"

        meta["flow"] = flow_stats
        _score_packet(model, meta, flow_stats)

        batch_texts.append(_build_embed_text(meta))
        batch_metas.append(meta)
        batch_ids.append(f"{capture_id}:{i}")
        batch_ts.append(meta["packet"]["timestamp"])

        if len(batch_texts) >= BATCH_SIZE:
            flush_batch()

    flush_batch()

    #Pass 2: L3/L4 flow summaries.
    for flow_idx, (flow_key, final_stats) in enumerate(tracker.finalize_all()):
        src_ip, dst_ip, src_port, dst_port, proto = flow_key

        final_stats = dict(final_stats)
        rep_meta = final_stats.pop("last_meta", None)
        if rep_meta is None:
            continue

        rep_meta = dict(rep_meta)
        rep_meta["flow"] = final_stats
        rep_meta["flow_record_type"] = "flow_summary"
        _score_summary(model, rep_meta, final_stats)

        pn = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
        text = (
            f"FLOW {src_ip}:{src_port} → {dst_ip}:{dst_port} [{pn}] "
            f"packets={final_stats.get('count', 0)} "
            f"duration={final_stats.get('duration', 0):.1f}s "
            f"bps={final_stats.get('bps', 0):.0f}"
        )

        batch_texts.append(text)
        batch_metas.append(rep_meta)
        batch_ids.append(f"{capture_id}:flow:{flow_idx}")
        batch_ts.append(rep_meta["packet"]["timestamp"])

        if len(batch_texts) >= BATCH_SIZE:
            flush_batch()

    #Pass 3: L2 summaries.
    for suffix, text, rep_meta, ts in _l2_summary_records(l2_trackers, model):
        batch_texts.append(text)
        batch_metas.append(rep_meta)
        batch_ids.append(f"{capture_id}:{suffix}")
        batch_ts.append(ts)

        if len(batch_texts) >= BATCH_SIZE:
            flush_batch()

    flush_batch()
    conn.close()

    _app._net_index_dirty = True
    flush_net_index()

    return added


def ingest_pcap_file_stream(path: str, capture_id: str):
    
    #Streaming PCAP ingest. This is what /netimp uses through /net/import_pcap_stream.
    #emits packet rows, flow_summary rows, and L2 behavior summary rows.
    
    packets = rdpcap(path)
    total = len(packets)
    model = load_model()
    tracker = FlowTracker()
    arp_tracker = ARPTracker()
    dhcp_tracker = DHCPTracker()
    mac_tracker = MACFloodTracker()
    stp_tracker = STPTracker()
    vlan_tracker = VLANTracker()
    l2_trackers = [arp_tracker, dhcp_tracker, mac_tracker, stp_tracker, vlan_tracker]
    embed_model = get_model()

    idx = get_net_index(dim=384)
    conn = net_db()
    cur = conn.cursor()

    batch_texts = []
    batch_metas = []
    batch_ids = []
    batch_ts = []
    added = 0

    yield (0, total)

    def flush_batch():
        nonlocal added
        if not batch_texts:
            return

        vecs = embed_model.encode(
            batch_texts,
            normalize_embeddings=True,
            batch_size=BATCH_SIZE,
            show_progress_bar=False,
        )
        vecs = np.asarray(vecs, dtype=np.float32)

        start_row = int(idx.ntotal)
        idx.add(vecs)

        rows = [
            (
                batch_ids[j],
                capture_id,
                batch_texts[j],
                batch_ts[j],
                json.dumps(batch_metas[j], ensure_ascii=False),
                start_row + j,
            )
            for j in range(len(batch_texts))
        ]

        cur.executemany(
            """
            INSERT OR IGNORE INTO net_memories
            (id, capture_id, text, created_at, meta_json, faiss_row)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
        added += len(rows)

        batch_texts.clear()
        batch_metas.clear()
        batch_ids.clear()
        batch_ts.clear()

    #Pass 1: packet/l2_packet rows.
    for i, pkt in enumerate(packets):
        meta = _parse_packet(pkt, i)
        if meta is None:
            continue

        mac_tracker.update(meta)
        vlan_tracker.update(meta)

        app_proto = meta.get("layers", {}).get("application", {}).get("protocol")
        net_type = meta.get("layers", {}).get("network", {}).get("type")

        if app_proto == "ARP":
            flow_stats = arp_tracker.update(meta)
            meta["flow_record_type"] = "l2_packet"
        elif app_proto == "DHCP":
            flow_stats = dhcp_tracker.update(meta)
            meta["flow_record_type"] = "l2_packet"
        elif app_proto == "STP" or net_type in {"STP", "Ethernet"}:
            if app_proto == "STP":
                flow_stats = stp_tracker.update(meta)
            else:
                flow_stats = {}
            meta["flow_record_type"] = "l2_packet"
        else:
            flow_stats = tracker.update(meta)
            meta["flow_record_type"] = "packet"

        meta["flow"] = flow_stats
        _score_packet(model, meta, flow_stats)

        batch_texts.append(_build_embed_text(meta))
        batch_metas.append(meta)
        batch_ids.append(f"{capture_id}:{i}")
        batch_ts.append(meta["packet"]["timestamp"])

        if len(batch_texts) >= BATCH_SIZE:
            flush_batch()
            yield (added, total)

    flush_batch()
    yield (added, total)

    #Pass 2: L3/L4 flow summaries.
    for flow_idx, (flow_key, final_stats) in enumerate(tracker.finalize_all()):
        src_ip, dst_ip, src_port, dst_port, proto = flow_key

        final_stats = dict(final_stats)
        rep_meta = final_stats.pop("last_meta", None)
        if rep_meta is None:
            continue

        rep_meta = dict(rep_meta)
        rep_meta["flow"] = final_stats
        rep_meta["flow_record_type"] = "flow_summary"
        _score_summary(model, rep_meta, final_stats)

        pn = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
        text = (
            f"FLOW {src_ip}:{src_port} → {dst_ip}:{dst_port} [{pn}] "
            f"packets={final_stats.get('count', 0)} "
            f"duration={final_stats.get('duration', 0):.1f}s "
            f"bps={final_stats.get('bps', 0):.0f}"
        )

        batch_texts.append(text)
        batch_metas.append(rep_meta)
        batch_ids.append(f"{capture_id}:flow:{flow_idx}")
        batch_ts.append(rep_meta["packet"]["timestamp"])

        if len(batch_texts) >= BATCH_SIZE:
            flush_batch()
            yield (added, total)

    #Pass 3: L2 summaries.
    for suffix, text, rep_meta, ts in _l2_summary_records(l2_trackers, model):
        batch_texts.append(text)
        batch_metas.append(rep_meta)
        batch_ids.append(f"{capture_id}:{suffix}")
        batch_ts.append(ts)

        if len(batch_texts) >= BATCH_SIZE:
            flush_batch()
            yield (added, total)

    flush_batch()
    conn.close()

    _app._net_index_dirty = True
    flush_net_index()

    yield (added, total, capture_id)
