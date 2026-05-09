#Important design principle:
#    Packet rows are evidence. Attack decisions should come from l2_summary
#    records emitted by these trackers after observing behavior over time.


from __future__ import annotations

from collections import Counter, defaultdict, deque
from typing import Any

ARP_REPLY = 2
ARP_REQUEST = 1
ARP_WINDOW_SECONDS = 5.0
ARP_SUMMARY_MIN_REPLIES = 3


#Utility helpers

def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _duration(first: float, last: float) -> float:
    return max(float(last) - float(first), 0.0)


def _is_private_lan_ip(ip: str) -> bool:
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")


#ARP poisoning / gratuitous ARP behavior

class ARPTracker:
    def __init__(self) -> None:
        self._mac_to_ips: dict[str, set[str]] = defaultdict(set)
        self._ip_to_macs: dict[str, set[str]] = defaultdict(set)
        self._targets_by_mac: dict[str, set[str]] = defaultdict(set)
        self._reply_times_by_mac: dict[str, deque[float]] = defaultdict(deque)
        self._all_reply_times_by_mac: dict[str, list[float]] = defaultdict(list)
        self._reply_count_by_mac: dict[str, int] = defaultdict(int)
        self._request_count_by_mac: dict[str, int] = defaultdict(int)
        self._gratuitous_count_by_mac: dict[str, int] = defaultdict(int)
        self._first_seen_by_mac: dict[str, float] = {}
        self._last_seen_by_mac: dict[str, float] = {}
        self._last_meta_by_mac: dict[str, dict[str, Any]] = {}
        self._op_counts_by_mac: dict[str, Counter[int]] = defaultdict(Counter)
        self._pairs_by_mac: dict[str, Counter[tuple[str, str]]] = defaultdict(Counter)

    def update(self, meta: dict[str, Any]) -> dict[str, Any]:
        app = meta.get("layers", {}).get("application", {})
        if app.get("protocol") != "ARP":
            return {}

        ts = float(meta.get("packet", {}).get("timestamp", 0.0) or 0.0)
        op = int(app.get("op", 0) or 0)
        psrc = str(app.get("psrc") or "")
        pdst = str(app.get("pdst") or "")
        hwsrc = str(app.get("hwsrc") or "").lower()

        if not hwsrc:
            return {}

        if hwsrc not in self._first_seen_by_mac:
            self._first_seen_by_mac[hwsrc] = ts
        self._last_seen_by_mac[hwsrc] = ts
        self._last_meta_by_mac[hwsrc] = meta
        self._op_counts_by_mac[hwsrc][op] += 1

        if psrc:
            self._mac_to_ips[hwsrc].add(psrc)
            self._ip_to_macs[psrc].add(hwsrc)
        if pdst:
            self._targets_by_mac[hwsrc].add(pdst)
        if psrc and pdst:
            self._pairs_by_mac[hwsrc][(psrc, pdst)] += 1

        #Gratuitous ARP is usually sender IP == target IP, or a broadcast-style announcement. It is not malicious alone but storm behavior is scored later
        if psrc and pdst and psrc == pdst:
            self._gratuitous_count_by_mac[hwsrc] += 1

        if op == ARP_REPLY:
            self._reply_count_by_mac[hwsrc] += 1
            self._all_reply_times_by_mac[hwsrc].append(ts)
            q = self._reply_times_by_mac[hwsrc]
            q.append(ts)
            while q and (ts - q[0]) > ARP_WINDOW_SECONDS:
                q.popleft()
        elif op == ARP_REQUEST:
            self._request_count_by_mac[hwsrc] += 1

        return self._build_stats(hwsrc, psrc=psrc, pdst=pdst, op=op)

    def _bidirectional_pair_count(self, mac: str) -> int:
        pairs = self._pairs_by_mac.get(mac, Counter())
        count = 0
        for (a, b), n in pairs.items():
            if a and b and a != b and pairs.get((b, a), 0) > 0:
                count += min(n, pairs[(b, a)])
        return int(count // 2) if count > 1 else int(count)

    @staticmethod
    def _gateway_like(ip: str) -> bool:
        return bool(ip.endswith(".1") or ip.endswith(".254"))

    def _build_stats(self, mac: str, psrc: str = "", pdst: str = "", op: int = 0) -> dict[str, Any]:
        first = self._first_seen_by_mac.get(mac, 0.0)
        last = self._last_seen_by_mac.get(mac, first)
        duration = _duration(first, last)

        reply_window = self._reply_times_by_mac.get(mac, deque())
        claimed_ips = sorted(self._mac_to_ips.get(mac, set()))
        target_ips = sorted(self._targets_by_mac.get(mac, set()))

        changed_ips = []
        max_ip_mac_count = 0
        for ip in claimed_ips:
            n = len(self._ip_to_macs.get(ip, set()))
            max_ip_mac_count = max(max_ip_mac_count, n)
            if n >= 2:
                changed_ips.append(ip)

        reply_count = int(self._reply_count_by_mac.get(mac, 0))
        request_count = int(self._request_count_by_mac.get(mac, 0))
        gratuitous_count = int(self._gratuitous_count_by_mac.get(mac, 0))
        bidir_pairs = self._bidirectional_pair_count(mac)
        claimed_gateway_like = any(self._gateway_like(ip) for ip in claimed_ips)
        reply_burst = int(len(reply_window))
        rate_5s = float(reply_burst / ARP_WINDOW_SECONDS)
        total_rate = float(reply_count / max(duration, 1e-6)) if reply_count else 0.0

        #ARP poisoning confidence: multi-signal and deliberately not final. Poisoning is strongest when there is impersonation/conflict evidence,
        #especially bidirectional MITM-style pairs. Volume alone is not enough because a gratuitous ARP storm can also be very noisy
        poison_conf = 0.0
        if len(claimed_ips) >= 2: poison_conf += 0.18
        if len(claimed_ips) >= 3: poison_conf += 0.08
        if bool(changed_ips): poison_conf += 0.32
        if bidir_pairs >= 1: poison_conf += 0.22
        if bidir_pairs >= 5: poison_conf += 0.10
        if reply_count >= 10: poison_conf += 0.10
        elif reply_count >= 4: poison_conf += 0.06
        if reply_burst >= 6: poison_conf += 0.06
        if len(target_ips) >= 2: poison_conf += 0.08
        if claimed_gateway_like: poison_conf += 0.08

        #Gratuitous ARP storm confidence: separate from MITM poisoning. It is driven by repeated gratuitous announcements plus burst/rate behavior
        total_arp = max(reply_count + request_count, 1)
        garp_ratio = gratuitous_count / total_arp
        garp_conf = 0.0
        if gratuitous_count >= 5: garp_conf += 0.20
        if gratuitous_count >= 20: garp_conf += 0.30
        if reply_burst >= 10: garp_conf += 0.15
        if total_rate >= 2.0 and gratuitous_count >= 10: garp_conf += 0.20
        if len(target_ips) >= 3: garp_conf += 0.08
        if garp_ratio >= 0.60 and gratuitous_count >= 5: garp_conf += 0.15

        strong_mitm_pattern = bool((bidir_pairs >= 2) or (changed_ips and bidir_pairs >= 1))
        #If the dominant behavior is gratuitous announcement volume and not a strong MITM symmetry/conflict pattern, reduce poisoning confidence so
        #GRATUITOUS_ARP_STORM can win as the primary hypothesis
        if garp_conf >= 0.55 and garp_ratio >= 0.60 and not strong_mitm_pattern:
            poison_conf -= 0.22
        if duration > 180 and not changed_ips and bidir_pairs == 0: poison_conf -= 0.20
        if reply_count <= 2 and not changed_ips and bidir_pairs == 0: poison_conf -= 0.15
        poison_conf = _clamp01(poison_conf)
        garp_conf = _clamp01(garp_conf)

        return {
            "l2_protocol": "ARP",
            "arp_op": int(op),
            "arp_hwsrc": mac,
            "arp_psrc": psrc,
            "arp_pdst": pdst,
            "arp_reply_count": reply_count,
            "arp_request_count": request_count,
            "gratuitous_arp_count": gratuitous_count,
            "arp_reply_count_5s": reply_burst,
            "arp_reply_rate_5s": rate_5s,
            "arp_reply_rate_total": total_rate,
            "mac_claimed_ips": claimed_ips,
            "mac_claimed_ip_count": int(len(claimed_ips)),
            "target_ips": target_ips,
            "target_ip_count": int(len(target_ips)),
            "ip_mapping_changed": bool(changed_ips),
            "changed_ips": sorted(changed_ips),
            "max_ip_mac_count": int(max_ip_mac_count),
            "bidirectional_arp_pairs": int(bidir_pairs),
            "claimed_gateway_like": bool(claimed_gateway_like),
            "gratuitous_arp_ratio": float(garp_ratio),
            "strong_mitm_pattern": bool(strong_mitm_pattern),
            "duration": float(duration),
            "count": reply_count,
            "pps": total_rate,
            "bps": 0.0,
            "iat_mean": 0.0,
            "iat_std": 0.0,
            "unique_dst_ports": 0,
            "syn_ack_ratio": 0.0,
            "arp_poison_confidence": poison_conf,
            "arp_poison_candidate": bool(poison_conf >= 0.55),
            "gratuitous_arp_storm_confidence": garp_conf,
            "gratuitous_arp_storm_candidate": bool(garp_conf >= 0.55),
        }

    def finalize_all(self) -> list[tuple[tuple[str, str], dict[str, Any]]]:
        out: list[tuple[tuple[str, str], dict[str, Any]]] = []
        for mac in sorted(self._mac_to_ips.keys()):
            stats = self._build_stats(mac)
            if (
                stats["arp_poison_confidence"] >= 0.35
                or stats["gratuitous_arp_storm_confidence"] >= 0.35
                or stats["mac_claimed_ip_count"] >= 2
                or stats["ip_mapping_changed"]
                or stats["arp_reply_count"] >= ARP_SUMMARY_MIN_REPLIES
                or stats["gratuitous_arp_count"] >= 3
            ):
                stats["last_meta"] = self._last_meta_by_mac.get(mac)
                out.append((("ARP", mac), stats))
        return out



#DHCP starvation / exhaustion behavior

class DHCPTracker:
    def __init__(self) -> None:
        self._first_seen = 0.0
        self._last_seen = 0.0
        self._last_meta: dict[str, Any] | None = None
        self._msg_counts: Counter[str] = Counter()
        self._client_macs: set[str] = set()
        self._xids: set[int] = set()
        self._requested_ips: set[str] = set()
        self._times: deque[float] = deque()
        self._all_times: list[float] = []

    def update(self, meta: dict[str, Any]) -> dict[str, Any]:
        app = meta.get("layers", {}).get("application", {})
        if app.get("protocol") != "DHCP":
            return {}
        ts = float(meta.get("packet", {}).get("timestamp", 0.0) or 0.0)
        if self._first_seen == 0.0:
            self._first_seen = ts
        self._last_seen = ts
        self._last_meta = meta

        msg = str(app.get("message_type") or "UNKNOWN").upper()
        self._msg_counts[msg] += 1
        mac = str(app.get("client_mac") or app.get("chaddr") or "").lower()
        if mac:
            self._client_macs.add(mac)
        xid = app.get("xid")
        if xid is not None:
            try: self._xids.add(int(xid))
            except Exception: pass
        req_ip = str(app.get("requested_addr") or "")
        if req_ip:
            self._requested_ips.add(req_ip)

        self._times.append(ts)
        self._all_times.append(ts)
        while self._times and (ts - self._times[0]) > 10.0:
            self._times.popleft()
        return self._build_stats()

    def _build_stats(self) -> dict[str, Any]:
        duration = _duration(self._first_seen, self._last_seen)
        discovers = self._msg_counts.get("DISCOVER", 0)
        requests = self._msg_counts.get("REQUEST", 0)
        total = sum(self._msg_counts.values())
        unique_macs = len(self._client_macs)
        unique_xids = len(self._xids)
        burst_10s = len(self._times)
        rate = total / max(duration, 1e-6) if total else 0.0

        conf = 0.0
        #Starvation is many clients/xids requesting leases quickly
        if unique_macs >= 10: conf += 0.20
        if unique_macs >= 25: conf += 0.25
        if unique_xids >= 25: conf += 0.15
        if discovers + requests >= 20: conf += 0.15
        if discovers + requests >= 60: conf += 0.15
        if burst_10s >= 20: conf += 0.15
        if rate >= 5.0 and total >= 20: conf += 0.15
        #If it is one stable MAC doing normal DHCP renewal, reduce
        if unique_macs <= 2 and total <= 10: conf -= 0.25
        conf = _clamp01(conf)

        return {
            "l2_protocol": "DHCP",
            "dhcp_message_counts": dict(self._msg_counts),
            "dhcp_total_messages": int(total),
            "dhcp_discover_count": int(discovers),
            "dhcp_request_count": int(requests),
            "dhcp_unique_client_macs": int(unique_macs),
            "dhcp_unique_xids": int(unique_xids),
            "dhcp_requested_ip_count": int(len(self._requested_ips)),
            "dhcp_burst_10s": int(burst_10s),
            "dhcp_rate_total": float(rate),
            "duration": float(duration),
            "count": int(total),
            "pps": float(rate),
            "bps": 0.0,
            "iat_mean": 0.0,
            "iat_std": 0.0,
            "unique_dst_ports": 0,
            "syn_ack_ratio": 0.0,
            "dhcp_starvation_confidence": conf,
            "dhcp_starvation_candidate": bool(conf >= 0.55),
        }

    def finalize_all(self) -> list[tuple[tuple[str, str], dict[str, Any]]]:
        if not self._last_meta:
            return []
        stats = self._build_stats()
        if stats["dhcp_starvation_confidence"] >= 0.35 or stats["dhcp_total_messages"] >= 10:
            stats["last_meta"] = self._last_meta
            return [(("DHCP", "global"), stats)]
        return []


#MAC flood / CAM table exhaustion behavior

class MACFloodTracker:
    def __init__(self) -> None:
        self._first_seen = 0.0
        self._last_seen = 0.0
        self._last_meta: dict[str, Any] | None = None
        self._src_macs: set[str] = set()
        self._dst_macs: set[str] = set()
        self._times: deque[float] = deque()
        self._count = 0

    def update(self, meta: dict[str, Any]) -> dict[str, Any]:
        l2 = meta.get("layers", {}).get("l2", {})
        src = str(l2.get("eth_src") or "").lower()
        dst = str(l2.get("eth_dst") or "").lower()
        if not src:
            return {}
        ts = float(meta.get("packet", {}).get("timestamp", 0.0) or 0.0)
        if self._first_seen == 0.0:
            self._first_seen = ts
        self._last_seen = ts
        self._last_meta = meta
        self._count += 1
        self._src_macs.add(src)
        if dst:
            self._dst_macs.add(dst)
        self._times.append(ts)
        while self._times and (ts - self._times[0]) > 5.0:
            self._times.popleft()
        return self._build_stats()

    def _build_stats(self) -> dict[str, Any]:
        duration = _duration(self._first_seen, self._last_seen)
        unique_src = len(self._src_macs)
        burst_5s = len(self._times)
        rate = self._count / max(duration, 1e-6) if self._count else 0.0
        churn_ratio = unique_src / max(self._count, 1)

        conf = 0.0
        if unique_src >= 50: conf += 0.25
        if unique_src >= 200: conf += 0.30
        if burst_5s >= 100: conf += 0.20
        if rate >= 50 and unique_src >= 50: conf += 0.20
        if churn_ratio >= 0.70 and unique_src >= 50: conf += 0.20
        if unique_src < 20: conf -= 0.20
        conf = _clamp01(conf)

        return {
            "l2_protocol": "ETHERNET",
            "mac_flood_total_frames": int(self._count),
            "mac_flood_unique_src_macs": int(unique_src),
            "mac_flood_unique_dst_macs": int(len(self._dst_macs)),
            "mac_flood_burst_5s": int(burst_5s),
            "mac_flood_rate_total": float(rate),
            "mac_flood_churn_ratio": float(churn_ratio),
            "duration": float(duration),
            "count": int(self._count),
            "pps": float(rate),
            "bps": 0.0,
            "iat_mean": 0.0,
            "iat_std": 0.0,
            "unique_dst_ports": 0,
            "syn_ack_ratio": 0.0,
            "mac_flood_confidence": conf,
            "mac_flood_candidate": bool(conf >= 0.55),
        }

    def finalize_all(self) -> list[tuple[tuple[str, str], dict[str, Any]]]:
        if not self._last_meta:
            return []
        stats = self._build_stats()
        if stats["mac_flood_confidence"] >= 0.35:
            stats["last_meta"] = self._last_meta
            return [(("ETHERNET", "mac-flood"), stats)]
        return []



#STP root bridge manipulation behavior

class STPTracker:
    def __init__(self) -> None:
        self._first_seen = 0.0
        self._last_seen = 0.0
        self._last_meta: dict[str, Any] | None = None
        self._root_ids: Counter[str] = Counter()
        self._bridge_ids: Counter[str] = Counter()
        self._priorities: list[int] = []
        self._count = 0

    def update(self, meta: dict[str, Any]) -> dict[str, Any]:
        app = meta.get("layers", {}).get("application", {})
        if app.get("protocol") != "STP":
            return {}
        ts = float(meta.get("packet", {}).get("timestamp", 0.0) or 0.0)
        if self._first_seen == 0.0:
            self._first_seen = ts
        self._last_seen = ts
        self._last_meta = meta
        self._count += 1
        root = str(app.get("root_id") or "")
        bridge = str(app.get("bridge_id") or "")
        if root: self._root_ids[root] += 1
        if bridge: self._bridge_ids[bridge] += 1
        prio = app.get("root_priority")
        try:
            if prio is not None: self._priorities.append(int(prio))
        except Exception:
            pass
        return self._build_stats()

    def _build_stats(self) -> dict[str, Any]:
        duration = _duration(self._first_seen, self._last_seen)
        unique_roots = len(self._root_ids)
        min_priority = min(self._priorities) if self._priorities else None
        rate = self._count / max(duration, 1e-6) if self._count else 0.0
        dominant_root, dominant_count = (self._root_ids.most_common(1)[0] if self._root_ids else ("", 0))

        conf = 0.0
        #STP root manipulation is behavioral: a host repeatedly advertising a superior/root bridge, a root-ID change, or very low root priority
        if self._count >= 3: conf += 0.10
        if self._count >= 10: conf += 0.30
        if self._count >= 20: conf += 0.15
        if unique_roots >= 2: conf += 0.25
        if min_priority is not None and min_priority <= 8192: conf += 0.20
        if min_priority is not None and min_priority <= 4096: conf += 0.10
        if min_priority == 0: conf += 0.20
        if rate >= 1.0 and self._count >= 5: conf += 0.15
        if dominant_count >= 5 and (unique_roots >= 2 or min_priority is not None): conf += 0.10
        conf = _clamp01(conf)

        return {
            "l2_protocol": "STP",
            "stp_bpdu_count": int(self._count),
            "stp_unique_root_ids": int(unique_roots),
            "stp_root_ids": dict(self._root_ids),
            "stp_bridge_ids": dict(self._bridge_ids),
            "stp_min_root_priority": min_priority,
            "stp_dominant_root_id": dominant_root,
            "stp_rate_total": float(rate),
            "duration": float(duration),
            "count": int(self._count),
            "pps": float(rate),
            "bps": 0.0,
            "iat_mean": 0.0,
            "iat_std": 0.0,
            "unique_dst_ports": 0,
            "syn_ack_ratio": 0.0,
            "stp_root_attack_confidence": conf,
            "stp_root_attack_candidate": bool(conf >= 0.55),
        }

    def finalize_all(self) -> list[tuple[tuple[str, str], dict[str, Any]]]:
        if not self._last_meta:
            return []
        stats = self._build_stats()
        if stats["stp_root_attack_confidence"] >= 0.35 or stats["stp_bpdu_count"] >= 3:
            stats["last_meta"] = self._last_meta
            return [(("STP", "root"), stats)]
        return []



#VLAN double-tagging / VLAN hopping behavior

class VLANTracker:
    def __init__(self) -> None:
        self._first_seen = 0.0
        self._last_seen = 0.0
        self._last_meta: dict[str, Any] | None = None
        self._tagged_count = 0
        self._double_tagged_count = 0
        self._outer_vlans: Counter[int] = Counter()
        self._inner_vlans: Counter[int] = Counter()
        self._pairs: Counter[tuple[int, int]] = Counter()

    def update(self, meta: dict[str, Any]) -> dict[str, Any]:
        l2 = meta.get("layers", {}).get("l2", {})

        # Accept all field names used by older/newer ingest versions.
        vlan_ids = (
            l2.get("vlan_ids")
            or l2.get("vlan_tags")
            or l2.get("vlans")
            or []
        )

        #If the parser tells us this is VLAN tagged but failed to expose IDs, still track it as tagged behavior. It will not become VLAN_HOPPING
        #without double tag evidence, but it emits useful l2_summary stats
        eth_type = l2.get("eth_type")
        is_vlan_ethertype = eth_type in {0x8100, 0x88A8, 0x9100, 33024, 34984, 37120}
        if not vlan_ids and not is_vlan_ethertype:
            return {}

        ts = float(meta.get("packet", {}).get("timestamp", 0.0) or 0.0)
        if self._first_seen == 0.0:
            self._first_seen = ts
        self._last_seen = ts
        self._last_meta = meta
        self._tagged_count += 1

        try:
            vids = [int(v) for v in vlan_ids if v is not None]
        except Exception:
            vids = []

        if not vids and l2.get("outer_vlan") is not None:
            try:
                vids.append(int(l2.get("outer_vlan")))
            except Exception:
                pass
        if len(vids) < 2 and l2.get("inner_vlan") is not None:
            try:
                inner = int(l2.get("inner_vlan"))
                if not vids or inner != vids[-1]:
                    vids.append(inner)
            except Exception:
                pass

        if vids:
            self._outer_vlans[vids[0]] += 1

        explicit_double = bool(l2.get("double_tagged", False))
        if len(vids) >= 2 or explicit_double:
            self._double_tagged_count += 1
            if len(vids) >= 2:
                self._inner_vlans[vids[1]] += 1
                self._pairs[(vids[0], vids[1])] += 1
            elif len(vids) == 1:
                self._inner_vlans[-1] += 1
                self._pairs[(vids[0], -1)] += 1

        return self._build_stats()

    def _build_stats(self) -> dict[str, Any]:
        duration = _duration(self._first_seen, self._last_seen)
        rate = self._tagged_count / max(duration, 1e-6) if self._tagged_count else 0.0
        unique_inner = len(self._inner_vlans)
        unique_pairs = len(self._pairs)
        common_outer = self._outer_vlans.most_common(1)[0][0] if self._outer_vlans else None

        conf = 0.0
        #Double tagging is the core VLAN hopping behavior. One double tagged frame is already strong evidence so repeated pairs increase confidence
        if self._double_tagged_count >= 1: conf += 0.60
        if self._double_tagged_count >= 3: conf += 0.18
        if self._double_tagged_count >= 10: conf += 0.10
        if unique_inner >= 2: conf += 0.08
        if unique_pairs >= 2: conf += 0.08
        if common_outer in {0, 1}: conf += 0.12  # native/default VLAN as weak evidence
        conf = _clamp01(conf)

        return {
            "l2_protocol": "VLAN",
            "vlan_tagged_count": int(self._tagged_count),
            "vlan_double_tagged_count": int(self._double_tagged_count),
            "vlan_outer_ids": dict(self._outer_vlans),
            "vlan_inner_ids": dict(self._inner_vlans),
            "vlan_outer_id_list": sorted(self._outer_vlans.keys()),
            "vlan_inner_id_list": sorted(self._inner_vlans.keys()),
            "vlan_tag_pairs": {f"{a}->{b}": n for (a, b), n in self._pairs.items()},
            "vlan_unique_inner_ids": int(unique_inner),
            "vlan_unique_tag_pairs": int(unique_pairs),
            "vlan_common_outer_id": common_outer,
            "vlan_rate_total": float(rate),
            "duration": float(duration),
            "count": int(self._tagged_count),
            "pps": float(rate),
            "bps": 0.0,
            "iat_mean": 0.0,
            "iat_std": 0.0,
            "unique_dst_ports": 0,
            "syn_ack_ratio": 0.0,
            "vlan_hopping_confidence": conf,
            "vlan_hopping_candidate": bool(conf >= 0.55),
        }

    def finalize_all(self) -> list[tuple[tuple[str, str], dict[str, Any]]]:
        if not self._last_meta:
            return []
        stats = self._build_stats()
        if stats["vlan_hopping_confidence"] >= 0.35 or stats["vlan_double_tagged_count"] >= 1:
            stats["last_meta"] = self._last_meta
            return [(("VLAN", "double-tag"), stats)]
        return []
