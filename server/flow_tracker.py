import time
from collections import defaultdict
import numpy as np

FLOW_TIMEOUT_SECONDS = 120.0
MIN_FLOW_PACKETS     = 5
MAX_IAT_SAMPLES      = 100

#SYN flood aggregator thresholds
#The 5 tuple flow tracker cannot detect floods launched with randomised source ports, because every packet lands in its own unique flow and no single flow ever
# accumulates enough packets to be finalised. The flood aggregator uses a 3-tuple key (src_ip, dst_ip, dst_port) to collapse all source ports into
# one bucket, which is the correct level of granularity for this attack
FLOOD_SYN_THRESHOLD   = 50    # minimum SYNs to consider it a flood
FLOOD_RATIO_THRESHOLD = 10.0  # min syn/(ack+1) — nearly no responses
FLOOD_MIN_DURATION    = 1.0   # seconds — excludes single-packet bursts

#Scan aggregator thresholds
#A port scan touches many different destination ports from one source port
#Each probed port lands in its own 1 packet and 5tuple flow so none reach MIN_FLOW_PACKETS=5 so nothing is ever finalised via the normal path
#Key: (src_ip, dst_ip, src_port) [ignoring dst_port] collapses all probe packets from one scanner into one bucket. Mirrors the flood aggregator which
# keys on (src_ip, dst_ip, dst_port). Handles both XMAS scans (FIN+PSH+URG, variable dst_ports) and half-open SYN port scans (SYN-only, variable dst_ports).
SCAN_PORT_THRESHOLD = 20    #minimum unique dst_ports to confirm a scan
SCAN_MIN_DURATION   = 0.5   #seconds: excludes degenerate single burst captures

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10


class FlowTracker:
    def __init__(self):
        self._flows          = {}
        self._src_dst_ports  = defaultdict(set)
        self._completed      = {}
        #Flood aggregator: keyed on (src_ip, dst_ip, dst_port)
        #Ignores src_port so that random-sport SYN floods are collapsed into a single bucket instead of being split across thousands of
        #tiny 5-tuple flows that never reach MIN_FLOW_PACKETS.
        self._flood_buckets  = {}
        #Scan aggregator: keyed on (src_ip, dst_ip, src_port)
        #Ignores dst_port so that scans probing many destination ports are collapsed into one bucket. Complementary to the flood aggregator
        self._scan_buckets   = {}

    def _make_flow_key(self, src_ip, dst_ip, src_port, dst_port, proto):
        #Bidirectional key: A => B and B => A map to the same flow
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, proto)
        else:
            return (dst_ip, src_ip, dst_port, src_port, proto)

    def update(self, meta: dict) -> dict:
        network   = meta.get("layers", {}).get("network",   {})
        transport = meta.get("layers", {}).get("transport", {})
        packet    = meta.get("packet", {})

        src_ip    = network.get("src_ip",  "0.0.0.0")
        dst_ip    = network.get("dst_ip",  "0.0.0.0")
        src_port  = int(transport.get("src_port", 0) or 0)
        dst_port  = int(transport.get("dst_port", 0) or 0)
        proto     = int(network.get("protocol_number", 0))
        pkt_size  = int(packet.get("bytes", 0))
        ts        = float(packet.get("timestamp", time.time()))
        tcp_flags = int(transport.get("tcp_flags", 0) or 0)

        if dst_port > 0:
            self._src_dst_ports[src_ip].add(dst_port)

        #Update flood aggregator for every TCP SYN packet
        #Key is 3 tuple (src_ip, dst_ip, dst_port): src_port is intentionally excluded so that random-sport floods collapse into one bucket
        if proto == 6:  # TCP only
            flood_key = (src_ip, dst_ip, dst_port)
            if flood_key not in self._flood_buckets:
                self._flood_buckets[flood_key] = {
                    "syn":       0,
                    "ack":       0,
                    "start":     ts,
                    "last":      ts,
                    "last_meta": None,
                }
            fb = self._flood_buckets[flood_key]
            if tcp_flags & TCP_SYN:
                fb["syn"]  += 1
                fb["last"]  = ts
                fb["last_meta"] = meta
            if tcp_flags & TCP_ACK:
                fb["ack"]  += 1

        #Update scan aggregator for every TCP packet directed at a dst_port > 0
        #Key is (src_ip, dst_ip, src_port): dst_port intentionally excluded so that scans hitting many different ports collapse into one bucket
        if proto == 6 and dst_port > 0 and src_port > 0:
            scan_key = (src_ip, dst_ip, src_port)
            if scan_key not in self._scan_buckets:
                self._scan_buckets[scan_key] = {
                    "dst_ports": set(),
                    "xmas":      0,
                    "syn":       0,
                    "start":     ts,
                    "last":      ts,
                    "last_meta": None,
                }
            sb = self._scan_buckets[scan_key]
            sb["dst_ports"].add(dst_port)
            sb["last"]      = ts
            sb["last_meta"] = meta
            if (tcp_flags & 0x29) == 0x29:          # FIN+PSH+URG = XMAS
                sb["xmas"] += 1
            elif (tcp_flags & 0x02) and not (tcp_flags & 0x10):  # SYN-only
                sb["syn"]  += 1

        flow_key = self._make_flow_key(src_ip, dst_ip, src_port, dst_port, proto)

        if flow_key not in self._flows:
            self._flows[flow_key] = {
                "count":        0,
                "bytes":        0,
                "start":        ts,
                "last":         ts,
                "iats":         [],
                "last_fwd_ts":  None,
                "syn_count":    0,
                "ack_count":    0,
                "fin_seen":     False,
                "rst_seen":     False,
                "fwd_count":    0,
                "bwd_count":    0,
                "fwd_bytes":    0,
                "bwd_bytes":    0,
                "is_forward":   None,
                "last_meta":    None,
                "syn_ack_seen": False,
            }

        f = self._flows[flow_key]

        #Direction detection: first packet sets the forward direction
        if f["is_forward"] is None:
            f["is_forward"] = (src_ip, src_port)

        if (src_ip, src_port) == f["is_forward"]:
            direction = "fwd"
            f["fwd_count"] += 1
            f["fwd_bytes"] += pkt_size
        else:
            direction = "bwd"
            f["bwd_count"] += 1
            f["bwd_bytes"] += pkt_size

        #Forward only IAT, so the ACK packets from receiver dont distort the list
        if direction == "fwd":
            if f["last_fwd_ts"] is not None:
                iat = ts - f["last_fwd_ts"]
                if iat >= 0 and len(f["iats"]) < MAX_IAT_SAMPLES:
                    f["iats"].append(iat)
            f["last_fwd_ts"] = ts

        f["count"]     += 1
        f["bytes"]     += pkt_size
        f["last"]       = ts
        f["last_meta"]  = meta

        if tcp_flags & TCP_SYN: f["syn_count"] += 1
        if tcp_flags & TCP_ACK: f["ack_count"] += 1
        if tcp_flags & TCP_FIN: f["fin_seen"]   = True
        if tcp_flags & TCP_RST: f["rst_seen"]   = True

        if (tcp_flags & TCP_SYN) and (tcp_flags & TCP_ACK):
            f["syn_ack_seen"] = True

        if (f["fin_seen"] or f["rst_seen"]) and f["count"] >= MIN_FLOW_PACKETS:
            self._finalize_flow(flow_key)

        return self._compute_stats(flow_key, f, src_ip)

    def _compute_stats(self, flow_key, f, src_ip) -> dict:
        duration = max(f["last"] - f["start"], 1e-6)
        iats     = f["iats"]
        iat_mean = float(np.mean(iats)) if len(iats) >= 2 else 0.0
        iat_std  = float(np.std(iats))  if len(iats) >= 3 else 0.0

        return {
            "count":            f["count"],
            "bytes":            f["bytes"],
            "duration":         duration,
            "pps":              f["count"] / duration,
            "bps":              f["bytes"] / duration,
            "iat_mean":         iat_mean,
            "iat_std":          iat_std,
            "fwd_ratio":        f["fwd_count"] / (f["bwd_count"] + 1),
            "unique_dst_ports": len(self._src_dst_ports.get(src_ip, set())),
            "syn_ack_ratio":    f["syn_count"] / (f["ack_count"] + 1),
            "fwd_packets":      f["fwd_count"],
            "bwd_packets":      f["bwd_count"],
            "syn_only_flow":    not f["syn_ack_seen"],
        }

    def _finalize_flow(self, flow_key) -> None:
        if flow_key not in self._flows:
            return
        f = self._flows[flow_key]
        if f["count"] < MIN_FLOW_PACKETS:
            del self._flows[flow_key]
            return
        src_ip = flow_key[0]
        stats  = self._compute_stats(flow_key, f, src_ip)
        stats["last_meta"] = f["last_meta"]
        stats["flow_key"]  = flow_key
        stats["fin_seen"]  = f["fin_seen"]
        stats["rst_seen"]  = f["rst_seen"]
        self._completed[flow_key] = stats
        del self._flows[flow_key]

    def pop_completed_flows(self) -> list:
        items = list(self._completed.items())
        self._completed.clear()
        return items

    def evict_stale(self, current_time: float | None = None) -> int:
        if current_time is None:
            current_time = time.time()
        evicted = 0
        for k in list(self._flows.keys()):
            f = self._flows[k]
            if (current_time - f["last"]) > FLOW_TIMEOUT_SECONDS:
                if f["count"] >= MIN_FLOW_PACKETS:
                    self._finalize_flow(k)
                else:
                    del self._flows[k]
                evicted += 1
        return evicted

    def finalize_all(self) -> list:
        #Finalize all active flows regardless of timeout, then emit any SYN flood summaries from the flood aggregator

        #Call at end of PCAP ingest to capture:
        #   Long-lived connections that never sent FIN/RST (ongoing exfil)
        #   SYN floods with randomised source ports (aggregated by 3-tuple)
        for key in list(self._flows.keys()):
            f = self._flows[key]
            if f["count"] >= MIN_FLOW_PACKETS:
                self._finalize_flow(key)
            else:
                del self._flows[key]

        for flood_key, fb in list(self._flood_buckets.items()):
            src_ip, dst_ip, dst_port = flood_key
            syn_count = fb["syn"]
            ack_count = fb["ack"]
            duration  = max(fb["last"] - fb["start"], 1e-6)
            ratio     = syn_count / (ack_count + 1)

            if (syn_count  >= FLOOD_SYN_THRESHOLD and
                ratio      >  FLOOD_RATIO_THRESHOLD and
                duration   >= FLOOD_MIN_DURATION):

                #Build stats in the same shape as _compute_stats() so that extract_features() and predict() receive familiar keys
                pkt_size_est = 74  # Ether(14)+IP(20)+TCP(40) — typical SYN
                synthetic_stats = {
                    "count":            syn_count,
                    "bytes":            syn_count * pkt_size_est,
                    "duration":         duration,
                    "pps":              syn_count / duration,
                    "bps":              (syn_count * pkt_size_est) / duration,
                    "iat_mean":         duration / max(syn_count - 1, 1),
                    "iat_std":          0.0,   #not computed; not needed for flood detection
                    "fwd_ratio":        1.0,   #all packets are attacker => victim
                    "unique_dst_ports": 1,
                    "syn_ack_ratio":    ratio,
                    "fwd_packets":      syn_count,
                    "bwd_packets":      0,
                    "syn_only_flow":    ack_count == 0,
                    "last_meta":        fb["last_meta"],
                    "flow_key":         (src_ip, dst_ip, 0, dst_port, 6),
                    "fin_seen":         False,
                    "rst_seen":         False,
                    "flood_aggregated": True,  #tag for downstream consumers
                }
                synthetic_key = (src_ip, dst_ip, 0, dst_port, 6)
                self._completed[synthetic_key] = synthetic_stats

        self._flood_buckets.clear()

        for scan_key, sb in list(self._scan_buckets.items()):
            src_ip, dst_ip, src_port = scan_key
            unique_ports = len(sb["dst_ports"])
            duration     = max(sb["last"] - sb["start"], 1e-6)

            if unique_ports >= SCAN_PORT_THRESHOLD and duration >= SCAN_MIN_DURATION:
                #Dominant flag: XMAS if any XMAS packets seen, else SYN-only
                dominant_flags = 0x29 if sb["xmas"] > 0 else 0x02
                scan_count     = sb["xmas"] + sb["syn"]

                #Build a representative meta from the last packet but override transport flags to reflect the dominant scan flag type
                last_meta = sb["last_meta"]
                if last_meta is not None:
                    import copy
                    synth_meta = copy.deepcopy(last_meta)
                    synth_meta["layers"]["transport"]["tcp_flags"] = dominant_flags
                else:
                    synth_meta = None

                synthetic_stats = {
                    "count":            scan_count,
                    "bytes":            scan_count * 60,   #typical scan packet size
                    "duration":         duration,
                    "pps":              scan_count / duration,
                    "bps":              (scan_count * 60) / duration,
                    "iat_mean":         duration / max(scan_count - 1, 1),
                    "iat_std":          0.0,
                    "fwd_ratio":        1.0,
                    "unique_dst_ports": unique_ports,
                    "syn_ack_ratio":    0.0,              #no responses in a scan
                    "fwd_packets":      scan_count,
                    "bwd_packets":      0,
                    "syn_only_flow":    True,             #no SYN-ACK observed
                    "last_meta":        synth_meta,
                    "flow_key":         (src_ip, dst_ip, src_port, 0, 6),
                    "fin_seen":         False,
                    "rst_seen":         False,
                    "scan_aggregated":  True,             #tag for downstream consumers
                    "xmas_count":       sb["xmas"],
                    "syn_count":        sb["syn"],
                }
                synthetic_key = (src_ip, dst_ip, src_port, 0, 6)
                self._completed[synthetic_key] = synthetic_stats

        self._scan_buckets.clear()
        return self.pop_completed_flows()

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)
