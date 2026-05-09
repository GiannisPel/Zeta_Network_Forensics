#Supported families:
#  L2:  ARP_POISONING, GRATUITOUS_ARP_STORM, DHCP_STARVATION,
#       MAC_FLOOD, STP_ROOT_ATTACK, VLAN_HOPPING
#  L3:  ICMP_TUNNELING, FRAGMENTATION_EVASION, LOW_TTL
#  L4:  XMAS_SCAN, STEALTH_SCAN, PORT_SCAN, SYN_FLOOD, BEACONING,
#       LOW_AND_SLOW_EXFIL, AUTOMATED_TRAFFIC
#  L7-ish: DNS_TUNNELING, DNS_RECON


from __future__ import annotations

import os
from typing import Any

import joblib
import numpy as np

MODEL_PATH = os.environ.get("ANOMALY_MODEL_PATH", "anomaly_model.pkl")

N_FEATURES = 20
MIN_FLOW_PACKETS = 5
MIN_FLOW_DURATION = 5.0

COMMON_PORTS = {
    80, 443, 8080, 8443,
    22,
    53, 5353, 5355,
    1900,
    8006, 8000, 8008, 8009,
    3389, 3306, 5432,
}

_HIGH_PORT_WHITELIST = {
    "192.168.1.50",
    "192.168.1.125",
}

SPECIFICITY = {
    "ARP_POISONING": 100,
    "STP_ROOT_ATTACK": 98,
    "VLAN_HOPPING": 96,
    "DHCP_STARVATION": 94,
    "MAC_FLOOD": 93,
    "GRATUITOUS_ARP_STORM": 90,
    "SYN_FLOOD": 95,
    "XMAS_SCAN": 92,
    "DNS_TUNNELING": 88,
    "ICMP_TUNNELING": 86,
    "LOW_AND_SLOW_EXFIL": 82,
    "PORT_SCAN": 74,
    "STEALTH_SCAN": 70,
    "BEACONING": 68,
    "DNS_RECON": 60,
    "FRAGMENTATION_EVASION": 55,
    "HIGH_RATE_FLOOD": 50,
    "AUTOMATED_TRAFFIC": 35,
    "LOW_TTL": 25,
    "SUSPICIOUS_ARP": 20,
    "ANOMALOUS_TRAFFIC": 0,
}


def load_model():
    return joblib.load(MODEL_PATH)


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def extract_features(meta: dict, flow_stats: dict | None = None) -> list:
    network = meta.get("layers", {}).get("network", {})
    transport = meta.get("layers", {}).get("transport", {})
    app = meta.get("layers", {}).get("application", {})
    packet = meta.get("packet", {})

    protocol = int(network.get("protocol_number", 0) or 0)
    src_port = int(transport.get("src_port", 0) or 0)
    dst_port = int(transport.get("dst_port", 0) or 0)
    packet_size = int(packet.get("bytes", 0) or 0)
    tcp_flags = int(transport.get("tcp_flags", 0) or 0)
    ttl = int(network.get("ttl", 0) or 0)
    is_fragment = int(bool(network.get("is_fragment", False)))

    header_size = int(packet.get("header_size", 0) or 0)
    payload_bytes = max(0, packet_size - header_size)
    payload_ratio = payload_bytes / packet_size if packet_size > 0 else 0.0

    dns_query_length = 0
    dns_answer_count = 0
    dns_is_response = 0

    if app.get("protocol") == "DNS":
        dns_query_length = int(app.get("query_length", 0) or 0)
        dns_answer_count = int(app.get("answer_count", 0) or 0)
        dns_is_response = int(bool(app.get("is_response", False)))

    flow_packet_count = 0
    flow_bytes_total = 0
    flow_duration = 0.0
    flow_pps = 0.0
    flow_bps = 0.0
    iat_mean = 0.0
    iat_std = 0.0
    unique_dst_ports = 0
    syn_ack_ratio = 0.0

    if flow_stats:
        flow_packet_count = int(flow_stats.get("count", 0) or 0)
        flow_bytes_total = int(flow_stats.get("bytes", 0) or 0)
        flow_duration = float(flow_stats.get("duration", 0.0) or 0.0)
        flow_pps = float(flow_stats.get("pps", 0.0) or 0.0)
        flow_bps = float(flow_stats.get("bps", 0.0) or 0.0)
        iat_mean = float(flow_stats.get("iat_mean", 0.0) or 0.0)
        iat_std = float(flow_stats.get("iat_std", 0.0) or 0.0)
        unique_dst_ports = int(flow_stats.get("unique_dst_ports", 0) or 0)
        syn_ack_ratio = float(flow_stats.get("syn_ack_ratio", 0.0) or 0.0)

    return [
        protocol, src_port, dst_port, packet_size, tcp_flags, ttl, is_fragment,
        payload_ratio, dns_query_length, dns_answer_count, dns_is_response,
        flow_packet_count, flow_bytes_total, flow_duration, flow_pps, flow_bps,
        iat_mean, iat_std, unique_dst_ports, syn_ack_ratio,
    ]


def predict(
    model,
    features: list,
    meta: dict | None = None,
    flow_stats: dict | None = None,
    is_flow_summary: bool = False,
) -> dict:
    score = float(model.decision_function([features])[0])
    pred = int(model.predict([features])[0])
    if_anomaly = pred == -1

    reasons = _explain(features, meta, flow_stats)
    candidate_scores = _candidate_scores(features, meta, flow_stats, reasons)
    attack_type, confidence = _choose_attack(candidate_scores)

    #Promotion discipline:
    # Packet rows are evidence, not incidents. Only hard structural packet proofs may promote at packet level. Behavioral attacks must be emitted as
    # flow_summary/l2_summary records so weak IF-only packet noise cannot explode
    # into fake STEALTH_SCAN/PORT_SCAN/HIGH_RATE_FLOOD findings
    specific_packet_families = {
        "XMAS_SCAN", "DNS_TUNNELING", "ICMP_TUNNELING",
        "FRAGMENTATION_EVASION", "LOW_TTL",
    }
    strong_behavior = bool(is_flow_summary and confidence >= 0.55)
    strong_packet = bool(
        (not is_flow_summary)
        and attack_type in specific_packet_families
        and confidence >= 0.78
    )

    is_anomaly = bool(strong_behavior or strong_packet)

    #SUSPICIOUS_ARP and ANOMALOUS_TRAFFIC are explanation / context labels only
    if attack_type in {"SUSPICIOUS_ARP", "ANOMALOUS_TRAFFIC"}:
        is_anomaly = False

    severity = _behavioral_severity(attack_type, confidence, features, flow_stats, is_anomaly)

    return {
        "anomaly": is_anomaly,
        "score": score,
        "reasons": reasons,
        "attack_type": attack_type if is_anomaly else (attack_type if confidence >= 0.40 else "ANOMALOUS_TRAFFIC"),
        "confidence": round(float(confidence), 3),
        "severity": severity,
        "candidate_scores": {k: round(float(v), 3) for k, v in candidate_scores.items() if v > 0.0},
    }


def _choose_attack(candidate_scores: dict[str, float]) -> tuple[str, float]:
    if not candidate_scores:
        return "ANOMALOUS_TRAFFIC", 0.0

    #choose by confidence first, specificity as deterministic tie breaker
    best = max(candidate_scores.items(), key=lambda kv: (kv[1], SPECIFICITY.get(kv[0], 0)))
    return best[0], float(best[1])


def _candidate_scores(features: list, meta: dict | None, flow_stats: dict | None, reasons: list[str]) -> dict[str, float]:
    scores: dict[str, float] = {}
    combined = " ".join(reasons).lower()

    protocol = features[0]
    src_port = features[1]
    dst_port = features[2]
    packet_size = features[3]
    tcp_flags = features[4]
    is_fragment = features[6]
    dns_query_length = features[8]
    dns_answer_count = features[9]
    dns_is_response = features[10]
    flow_count = features[11]
    duration = features[13]
    pps = features[14]
    bps = features[15]
    iat_mean = features[16]
    iat_std = features[17]
    unique_ports = features[18]
    syn_ack_ratio = features[19]

    src_ip = ""
    dst_ip = ""
    app = {}
    if meta:
        network = meta.get("layers", {}).get("network", {})
        src_ip = str(network.get("src_ip", ""))
        dst_ip = str(network.get("dst_ip", ""))
        app = meta.get("layers", {}).get("application", {})

    #Suppress local/multicast discovery noise before L3/L4 candidate scoring.
    #ARP is handled by the L2 branch below, but fe80/ff02/multicast chatter should not become PORT_SCAN or FLOOD incidents
    l2_proto_for_suppress = (flow_stats or {}).get("l2_protocol") or app.get("protocol")
    if l2_proto_for_suppress not in {"ARP", "DHCP", "ETHERNET", "STP", "VLAN"}:
        if src_ip.startswith(("fe80", "ff02", "224.", "239.", "255.")) or dst_ip.startswith(("fe80", "ff02", "224.", "239.", "255.")):
            return {}

    #L2 families
    fs = flow_stats or {}
    l2_proto = fs.get("l2_protocol") or app.get("protocol")

    if l2_proto == "ARP":
        poison_conf = float(fs.get("arp_poison_confidence", 0.0) or 0.0)
        #Fallback if using older ARPTracker without precomputed confidence
        if poison_conf <= 0:
            claimed = int(fs.get("mac_claimed_ip_count", 0) or 0)
            replies = int(fs.get("arp_reply_count", 0) or 0)
            burst = int(fs.get("arp_reply_count_5s", 0) or 0)
            bidir = int(fs.get("bidirectional_arp_pairs", 0) or 0)
            changed = bool(fs.get("ip_mapping_changed", False))
            poison_conf = 0.0
            if claimed >= 2: poison_conf += 0.20
            if claimed >= 3: poison_conf += 0.10
            if changed: poison_conf += 0.30
            if bidir >= 1: poison_conf += 0.25
            if replies >= 10: poison_conf += 0.15
            elif replies >= 4: poison_conf += 0.08
            if burst >= 6: poison_conf += 0.10
            if int(fs.get("target_ip_count", 0) or 0) >= 2: poison_conf += 0.10
            poison_conf = _clamp01(poison_conf)

        garp_conf = float(fs.get("gratuitous_arp_storm_confidence", 0.0) or 0.0)
        garp_count = int(fs.get("gratuitous_arp_count", 0) or 0)
        garp_ratio = float(fs.get("gratuitous_arp_ratio", 0.0) or 0.0)
        strong_mitm = bool(fs.get("strong_mitm_pattern", False))

        #Competing ARP hypotheses:
        # Poisoning wins with conflict + MITM symmetry
        # Gratuitous storm wins with repeated gratuitous announcements and no strong MITM pattern. This avoids calling every GARP flood poisoning
        if garp_conf >= 0.55:
            scores["GRATUITOUS_ARP_STORM"] = garp_conf
            #If gratuitous announcement volume dominates, do not let the generic multi IP ARP poison hypothesis win unless there is a very
            #strong MITM/conflict pattern. This keeps GARP storms from being mislabeled as poisoning
            if garp_count >= 5 and garp_ratio >= 0.60 and not strong_mitm:
                poison_conf = min(poison_conf, max(0.0, garp_conf - 0.15))
            elif garp_count >= 20 and garp_ratio >= 0.45 and poison_conf <= garp_conf + 0.20:
                poison_conf = min(poison_conf, max(0.0, garp_conf - 0.10))

        if poison_conf >= 0.55:
            scores["ARP_POISONING"] = poison_conf
        elif poison_conf >= 0.35:
            scores["SUSPICIOUS_ARP"] = poison_conf

    elif l2_proto == "DHCP":
        conf = float(fs.get("dhcp_starvation_confidence", 0.0) or 0.0)
        if conf >= 0.55:
            scores["DHCP_STARVATION"] = conf

    elif l2_proto == "ETHERNET":
        conf = float(fs.get("mac_flood_confidence", 0.0) or 0.0)
        if conf >= 0.55:
            scores["MAC_FLOOD"] = conf

    elif l2_proto == "STP":
        conf = float(fs.get("stp_root_attack_confidence", 0.0) or 0.0)
        #Fallback for captures where Scapy cannot expose priority/root fields:
        #repeated BPDUs are still suspicious in a host/lab capture, but only become an attack when the behavioral summary is strong enough
        bpdu_count = int(fs.get("stp_bpdu_count", 0) or 0)
        unique_roots = int(fs.get("stp_unique_root_ids", 0) or 0)
        min_prio = fs.get("stp_min_root_priority")
        if conf <= 0:
            if bpdu_count >= 10: conf += 0.35
            if bpdu_count >= 20: conf += 0.20
            if unique_roots >= 2: conf += 0.25
            try:
                if min_prio is not None and int(min_prio) <= 8192: conf += 0.25
            except Exception:
                pass
            conf = _clamp01(conf)
        if conf >= 0.55:
            scores["STP_ROOT_ATTACK"] = conf

    elif l2_proto == "VLAN":
        conf = float(fs.get("vlan_hopping_confidence", 0.0) or 0.0)
        double_tagged = int(fs.get("vlan_double_tagged_count", 0) or 0)
        unique_pairs = int(fs.get("vlan_unique_tag_pairs", 0) or 0)
        if conf <= 0:
            if double_tagged >= 1: conf += 0.75
            if double_tagged >= 3: conf += 0.12
            if unique_pairs >= 2: conf += 0.08
            conf = _clamp01(conf)
        else:
            #A single confirmed double-tagged frame is strong structural evidence of VLAN hopping / double tagging.
            if double_tagged >= 1:
                conf = max(conf, 0.75)
        if conf >= 0.55:
            scores["VLAN_HOPPING"] = conf

    #Structural / content proof
    is_xmas = bool(tcp_flags and (tcp_flags & 0x29) == 0x29)
    if is_xmas:
        scores["XMAS_SCAN"] = _clamp01(0.82 + min(unique_ports, 200) / 1000.0)

    if dns_query_length > 100:
        scores["DNS_TUNNELING"] = _clamp01(0.72 + min(dns_query_length - 100, 200) / 500.0)

    if protocol == 1 and packet_size > 200:
        scores["ICMP_TUNNELING"] = _clamp01(0.68 + min(packet_size - 200, 1200) / 2400.0)

    if is_fragment:
        scores["FRAGMENTATION_EVASION"] = max(scores.get("FRAGMENTATION_EVASION", 0.0), 0.55)

    if 0 < features[5] < 10:
        scores["LOW_TTL"] = max(scores.get("LOW_TTL", 0.0), 0.35)

    #Scan / flood behavior
    if syn_ack_ratio > 10 and flow_count > 20:
        scores["SYN_FLOOD"] = _clamp01(0.70 + min(syn_ack_ratio, 50.0) / 100.0 + min(flow_count, 500) / 2000.0)

    #Port scan is spread behavior, not a single-packet finding. Require enough
    #accumulated flow evidence so random per-host UDP/HTTPS chatter does not promote.
    if unique_ports >= 20 and flow_count >= 10 and src_ip not in _HIGH_PORT_WHITELIST:
        scores["PORT_SCAN"] = _clamp01(0.35 + min(unique_ports, 250) / 300.0)

    syn_only_flow = bool((flow_stats or {}).get("syn_only_flow", False))
    #Stealth scan means TCP half-open/no-response behavior. UDP timing patterns
    #and normal HTTPS/QUIC flows must never be classified as SYN stealth scans.
    if (
        protocol == 6
        and syn_only_flow
        and syn_ack_ratio < 0.2
        and flow_count >= 5
        and unique_ports >= 5
    ):
        scores["STEALTH_SCAN"] = _clamp01(
            0.55 + min(flow_count, 100) / 200.0 + min(unique_ports, 50) / 200.0
        )

    #If XMAS is present, it is the specific subtype: keep generic scan secondary.
    if scores.get("XMAS_SCAN", 0.0) > 0:
        scores["PORT_SCAN"] = min(scores.get("PORT_SCAN", 0.0), scores["XMAS_SCAN"] - 0.08)
        scores["STEALTH_SCAN"] = min(scores.get("STEALTH_SCAN", 0.0), scores["XMAS_SCAN"] - 0.10)

    #Timing behavior
    if iat_std > 0 and iat_mean > 0 and flow_count >= 6:
        cv = iat_std / max(iat_mean, 1e-6)
        if duration > 30 and (iat_std < 0.1 or cv < 0.05):
            scores["BEACONING"] = max(scores.get("BEACONING", 0.0), _clamp01(0.48 + min(duration, 300) / 1000.0 + min(flow_count, 100) / 400.0))
        elif duration > 60 and iat_mean > 5.0 and 0.5 <= iat_std < 2.0:
            scores["BEACONING"] = max(scores.get("BEACONING", 0.0), _clamp01(0.55 + min(duration, 600) / 1200.0))
        elif flow_count > 10 and iat_std < 0.5 and iat_mean < 5.0:
            scores["AUTOMATED_TRAFFIC"] = max(scores.get("AUTOMATED_TRAFFIC", 0.0), 0.35)

    #Low and slow exfil: positive evidence minus competing hypotheses
    listener_port = min(src_port, dst_port) if src_port and dst_port else max(src_port, dst_port)
    exfil_positive = 0.0
    if protocol in {6, 17} and listener_port > 0 and listener_port not in COMMON_PORTS:
        if duration > 30: exfil_positive += 0.18
        if duration > 120: exfil_positive += 0.12
        if flow_count >= 10: exfil_positive += 0.12
        if 0 < bps < 5000: exfil_positive += 0.18
        if 0 < bps < 2000 and duration > 60: exfil_positive += 0.10
        if iat_std > 0: exfil_positive += 0.08
        if unique_ports <= 3: exfil_positive += 0.10

    scan_competition = max(scores.get("XMAS_SCAN", 0.0), scores.get("PORT_SCAN", 0.0), scores.get("STEALTH_SCAN", 0.0))
    exfil_score = _clamp01(exfil_positive - 0.55 * scan_competition)
    if exfil_score >= 0.45:
        scores["LOW_AND_SLOW_EXFIL"] = exfil_score

    if exfil_positive >= 0.45 and scan_competition >= 0.55:
        #Reason only so not a promoted label.
        pass

    if dns_answer_count == 0 and dns_is_response == 1:
        scores["DNS_RECON"] = max(scores.get("DNS_RECON", 0.0), 0.40)

    if flow_count >= 50 and pps > 500:
        scores["HIGH_RATE_FLOOD"] = max(
            scores.get("HIGH_RATE_FLOOD", 0.0),
            _clamp01(0.55 + min(pps, 5000) / 10000.0),
        )

    return {k: _clamp01(v) for k, v in scores.items() if v > 0}


def _behavioral_severity(attack_type: str, confidence: float, features: list, flow_stats: dict | None, is_anomaly: bool) -> str:
    if not is_anomaly:
        return "LOW"

    fs = flow_stats or {}
    duration = float(fs.get("duration", features[13] if len(features) > 13 else 0.0) or 0.0)
    count = int(fs.get("count", features[11] if len(features) > 11 else 0) or 0)
    unique_ports = int(fs.get("unique_dst_ports", features[18] if len(features) > 18 else 0) or 0)
    syn_ratio = float(fs.get("syn_ack_ratio", features[19] if len(features) > 19 else 0.0) or 0.0)
    arp_replies = int(fs.get("arp_reply_count", 0) or 0)
    arp_claimed = int(fs.get("mac_claimed_ip_count", 0) or 0)
    arp_bidir = int(fs.get("bidirectional_arp_pairs", 0) or 0)
    dhcp_clients = int(fs.get("dhcp_unique_client_macs", 0) or 0)
    mac_unique = int(fs.get("mac_flood_unique_src_macs", 0) or 0)
    vlan_double = int(fs.get("vlan_double_tagged_count", 0) or 0)
    stp_roots = int(fs.get("stp_unique_root_ids", 0) or 0)

    risk = confidence

    if duration > 60: risk += 0.06
    if duration > 180: risk += 0.06
    if count > 50: risk += 0.05
    if count > 200: risk += 0.06
    if unique_ports > 50: risk += 0.08
    if unique_ports > 150: risk += 0.08

    if attack_type == "ARP_POISONING":
        risk += 0.10
        if arp_claimed >= 3: risk += 0.08
        if arp_replies >= 20: risk += 0.08
        if arp_bidir >= 1: risk += 0.10
    elif attack_type == "GRATUITOUS_ARP_STORM":
        risk += 0.08
        if arp_replies >= 20: risk += 0.06
        if arp_replies >= 50: risk += 0.10
    elif attack_type == "DHCP_STARVATION":
        risk += 0.10
        if dhcp_clients >= 25: risk += 0.10
    elif attack_type == "MAC_FLOOD":
        risk += 0.10
        if mac_unique >= 200: risk += 0.12
    elif attack_type == "STP_ROOT_ATTACK":
        risk += 0.15
        if stp_roots >= 2: risk += 0.08
    elif attack_type == "VLAN_HOPPING":
        risk += 0.12
        if vlan_double >= 3: risk += 0.08
    elif attack_type in {"DNS_TUNNELING", "ICMP_TUNNELING", "LOW_AND_SLOW_EXFIL"}:
        risk += 0.10
    elif attack_type == "SYN_FLOOD" and syn_ratio > 10:
        risk += 0.08
    elif attack_type in {"PORT_SCAN", "STEALTH_SCAN"}:
        risk += 0.02

    risk = _clamp01(risk)
    if risk >= 0.90:
        return "CRITICAL"
    if risk >= 0.70:
        return "HIGH"
    if risk >= 0.45:
        return "MEDIUM"
    return "LOW"


def _explain(features: list, meta: dict | None = None, flow_stats: dict | None = None) -> list[str]:
    reasons: list[str] = []

    network = meta.get("layers", {}).get("network", {}) if meta else {}
    transport = meta.get("layers", {}).get("transport", {}) if meta else {}
    app = meta.get("layers", {}).get("application", {}) if meta else {}

    src_ip = str(network.get("src_ip", ""))
    dst_ip = str(network.get("dst_ip", ""))
    for prefix in ("fe80", "ff02", "224.0.0", "255.255"):
        if src_ip.startswith(prefix) or dst_ip.startswith(prefix):
            return []

    protocol = features[0]
    src_port = features[1]
    dst_port = features[2]
    packet_size = features[3]
    tcp_flags = features[4]
    ttl = features[5]
    is_fragment = features[6]
    dns_query_length = features[8]
    dns_answer_count = features[9]
    dns_is_response = features[10]
    flow_count = features[11]
    duration = features[13]
    pps = features[14]
    bps = features[15]
    iat_mean = features[16]
    iat_std = features[17]
    unique_ports = features[18]
    syn_ack_ratio = features[19]

    fs = flow_stats or {}

    #L2 explanations
    l2_proto = fs.get("l2_protocol") or app.get("protocol")

    if l2_proto == "ARP":
        poison_conf = float(fs.get("arp_poison_confidence", 0.0) or 0.0)
        garp_conf = float(fs.get("gratuitous_arp_storm_confidence", 0.0) or 0.0)
        claimed_ips = fs.get("mac_claimed_ips", [])
        changed_ips = fs.get("changed_ips", [])
        replies = int(fs.get("arp_reply_count", 0) or 0)
        garp = int(fs.get("gratuitous_arp_count", 0) or 0)
        burst = int(fs.get("arp_reply_count_5s", 0) or 0)
        bidir = int(fs.get("bidirectional_arp_pairs", 0) or 0)
        mac = fs.get("arp_hwsrc") or app.get("hwsrc", "?")

        garp_ratio = float(fs.get("gratuitous_arp_ratio", 0.0) or 0.0)
        strong_mitm = bool(fs.get("strong_mitm_pattern", False))

        if garp_conf >= 0.55 and garp >= 5 and garp_ratio >= 0.60 and not strong_mitm:
            reasons.append(
                f"Gratuitous ARP storm behavior (confidence={garp_conf:.2f}): MAC {mac}, "
                f"gratuitous_ARP={garp}, replies={replies}, burst={burst}/5s, ratio={garp_ratio:.2f}"
            )
            if poison_conf >= 0.35:
                reasons.append(
                    f"ARP poisoning candidate suppressed by stronger gratuitous-storm context "
                    f"(poison_confidence={poison_conf:.2f}, bidirectional_pairs={bidir})"
                )
        else:
            if poison_conf >= 0.55:
                reasons.append(
                    f"ARP poisoning behavior (confidence={poison_conf:.2f}): MAC {mac} claims {len(claimed_ips)} IPs {claimed_ips}, "
                    f"{replies} ARP replies, burst={burst}/5s, bidirectional_pairs={bidir}"
                )
            elif poison_conf >= 0.35:
                reasons.append(
                    f"Suspicious ARP behavior below poisoning threshold (confidence={poison_conf:.2f}): "
                    f"MAC {mac}, claimed_ips={claimed_ips}, replies={replies}, changed_ips={changed_ips}"
                )
            if garp_conf >= 0.55:
                reasons.append(
                    f"Gratuitous ARP storm behavior (confidence={garp_conf:.2f}): MAC {mac}, "
                    f"gratuitous_ARP={garp}, replies={replies}, burst={burst}/5s"
                )
        return reasons

    if l2_proto == "DHCP":
        conf = float(fs.get("dhcp_starvation_confidence", 0.0) or 0.0)
        if conf >= 0.55:
            reasons.append(
                f"DHCP starvation behavior (confidence={conf:.2f}): "
                f"unique_client_macs={fs.get('dhcp_unique_client_macs', 0)}, "
                f"unique_xids={fs.get('dhcp_unique_xids', 0)}, "
                f"DISCOVER={fs.get('dhcp_discover_count', 0)}, REQUEST={fs.get('dhcp_request_count', 0)}, "
                f"burst_10s={fs.get('dhcp_burst_10s', 0)}"
            )
        return reasons

    if l2_proto == "ETHERNET":
        conf = float(fs.get("mac_flood_confidence", 0.0) or 0.0)
        if conf >= 0.55:
            reasons.append(
                f"MAC flood behavior (confidence={conf:.2f}): "
                f"unique_src_macs={fs.get('mac_flood_unique_src_macs', 0)}, "
                f"frames={fs.get('mac_flood_total_frames', 0)}, "
                f"burst_5s={fs.get('mac_flood_burst_5s', 0)}, "
                f"churn_ratio={fs.get('mac_flood_churn_ratio', 0):.2f}"
            )
        return reasons

    if l2_proto == "STP":
        conf = float(fs.get("stp_root_attack_confidence", 0.0) or 0.0)
        if conf >= 0.55:
            reasons.append(
                f"STP root bridge manipulation behavior (confidence={conf:.2f}): "
                f"bpdu_count={fs.get('stp_bpdu_count', 0)}, "
                f"unique_root_ids={fs.get('stp_unique_root_ids', 0)}, "
                f"min_root_priority={fs.get('stp_min_root_priority')}"
            )
        return reasons

    if l2_proto == "VLAN":
        conf = float(fs.get("vlan_hopping_confidence", 0.0) or 0.0)
        double_tagged = int(fs.get("vlan_double_tagged_count", 0) or 0)
        if double_tagged >= 1:
            conf = max(conf, 0.75)
        if conf >= 0.55:
            reasons.append(
                f"VLAN hopping / double-tagging behavior (confidence={conf:.2f}): "
                f"double_tagged={fs.get('vlan_double_tagged_count', 0)}, "
                f"outer={fs.get('vlan_outer_ids', {})}, inner={fs.get('vlan_inner_ids', {})}"
            )
        return reasons

    flow_mature = flow_count >= MIN_FLOW_PACKETS and duration >= MIN_FLOW_DURATION
    syn_only_flow = bool(fs.get("syn_only_flow", False))
    is_xmas = bool(tcp_flags and (tcp_flags & 0x29) == 0x29)
    is_syn_only = bool((tcp_flags & 0x02) and not (tcp_flags & 0x10))
    scan_pattern = bool(protocol == 6 and unique_ports >= 5)

    if flow_mature and iat_std > 0 and iat_mean > 0:
        cv = iat_std / max(iat_mean, 1e-6)
        if flow_count > 10 and duration > 30.0 and (iat_std < 0.1 or cv < 0.05):
            reasons.append(
                f"Highly regular timing (iat_std={iat_std:.4f}s, mean={iat_mean:.2f}s, cv={cv:.3f}) — possible beaconing"
            )
        elif flow_count >= 6 and duration > 60.0 and iat_mean > 5.0 and 0.5 <= iat_std < 2.0:
            reasons.append(
                f"Periodic timing pattern (iat_std={iat_std:.4f}s, mean={iat_mean:.2f}s) — possible jittered C2 beaconing"
            )
        elif flow_count > 10 and iat_std < 0.5 and iat_mean < 5.0:
            reasons.append(f"Regular timing pattern (iat_std={iat_std:.4f}s) — possible automated traffic")

    #Low and slow exfil: positive behavior noted, scan competition explained.
    listener_port = min(src_port, dst_port) if src_port and dst_port else max(src_port, dst_port)
    exfil_positive = (
        protocol in {6, 17}
        and listener_port > 0
        and listener_port not in COMMON_PORTS
        and duration > 30.0
        and flow_count >= 10
        and 0 < bps < 5000
        and iat_std > 0
    )
    if exfil_positive:
        if is_xmas or unique_ports > 10 or (syn_only_flow and scan_pattern):
            reasons.append(
                f"Low-and-slow exfil candidate suppressed by stronger scan context: "
                f"bps={bps:.0f}, duration={duration:.0f}s, unique_ports={unique_ports}, flags=0x{tcp_flags:02x}"
            )
        else:
            reasons.append(
                f"Low-and-slow exfiltration pattern: {bps:.0f} Bps to port {listener_port} over {duration:.0f}s"
            )

    if iat_std > 0 and flow_count >= 50 and pps > 500:
        reasons.append(f"High packet rate ({pps:.0f} pps over {flow_count} packets) — possible flood")

    if tcp_flags != 0:
        if is_xmas:
            reasons.append("XMAS scan flags (FIN+PSH+URG)")
        if syn_ack_ratio > 10 and flow_count > 20:
            reasons.append(f"SYN flood pattern (ratio={syn_ack_ratio:.1f})")
        if is_syn_only:
            if not flow_mature and syn_only_flow:
                reasons.append("SYN-only packet (possible stealth scan)")
            elif flow_mature and syn_only_flow and flow_count >= 3 and scan_pattern:
                reasons.append(f"Half-open flow ({flow_count} SYN pkts, no SYN-ACK observed) — stealth scan confirmed")

    if unique_ports > 200 and src_ip not in _HIGH_PORT_WHITELIST:
        reasons.append(f"Extreme port scan ({unique_ports} unique destination ports)")
    elif unique_ports > 100 and src_ip not in _HIGH_PORT_WHITELIST:
        reasons.append(f"Port scan behavior ({unique_ports} unique destination ports)")
    elif unique_ports > 20 and is_xmas:
        reasons.append(f"XMAS scan spread across {unique_ports} destination ports")

    if dns_query_length > 100:
        reasons.append(f"Unusually long DNS query ({dns_query_length} chars) — possible tunneling")
    if dns_answer_count == 0 and dns_is_response == 1:
        reasons.append("DNS response with 0 answers — possible NXDOMAIN recon")
    if is_fragment:
        reasons.append("Fragmented IP packet — possible evasion")
    if 0 < ttl < 10:
        reasons.append(f"Very low TTL ({ttl}) — possible spoofed packet")
    if protocol == 1 and packet_size > 200:
        reasons.append(f"Large ICMP packet ({packet_size}B) — possible ICMP tunneling")

    return reasons
