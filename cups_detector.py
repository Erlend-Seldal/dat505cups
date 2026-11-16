#!/usr/bin/env python3
"""
cups_detector.py - detect suspicious cups-browsed discovery / IPP activity.

Monitors live traffic (--iface) or analyses a capture (--pcap) and raises
security alerts for the activity produced by CUPS printer-discovery abuse
(CVE-2024-47176 and friends):

  * UNAUTH_ADVERTISEMENT     - a legacy CUPS browse packet on UDP/631
  * UNEXPECTED_PRINTER_HOST  - advertised printer host not in --allow list
  * SOURCE_HOST_MISMATCH     - packet source IP != advertised printer host (spoofing)
  * MALFORMED_BROWSE         - browse payload that does not parse / is oversized / non-ASCII
  * REPEATED_DISCOVERY       - burst of browse packets from one source (flood)
  * SUSPICIOUS_IPP           - a victim-initiated IPP POST (the callback)

Alerts are printed and exported to CSV and/or JSON.

*** Use ONLY on your own isolated lab traffic. ***
"""

import argparse
import csv
import json
import logging
import re
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, PcapReader, IP, UDP, TCP, Raw
except ImportError:
    sys.exit("Scapy not found. Install with: sudo apt install -y python3-scapy")

VALID_SCHEMES = ("http", "https", "ipp", "ipps")
_URI_RE = re.compile(r'^(\w+)://([^/:]+)(?::(\d+))?(/.*)?$')


def _fmt(ts):
    return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def parse_browse(text):
    """Parse a legacy CUPS browse line: '<type> <state> <uri> \"loc\" \"info\" \"mm\"'.
    Returns (host, port, queue) or None if malformed."""
    toks = text.split(None, 2)
    if len(toks) < 3:
        return None
    ptype, state, rest = toks
    try:
        int(ptype, 0)
        int(state, 0)
    except ValueError:
        return None
    pieces = rest.split()
    if not pieces:
        return None
    m = _URI_RE.match(pieces[0])
    if not m or m.group(1) not in VALID_SCHEMES:
        return None
    host = m.group(2)
    port = m.group(3) or "631"
    path = m.group(4) or ""
    queue = path.rstrip("/").split("/")[-1] if path else ""
    return host, port, queue


class Detector:
    def __init__(self, allow=None, window=10.0, threshold=10,
                 disc_port=631, log=None):
        self.allow = set(allow or [])
        self.window = window
        self.threshold = threshold
        self.disc_port = disc_port
        self.log = log
        self.alerts = []
        self.recent = defaultdict(deque)      # src -> timestamps of browse pkts
        self.flood_flagged = set()

    def alert(self, ts, category, severity, src, dst, detail):
        rec = {"time": _fmt(ts), "category": category, "severity": severity,
               "src": src, "dst": dst, "detail": detail}
        self.alerts.append(rec)
        self.log.warning("[%-6s] %-24s %s -> %s | %s",
                         severity, category, src, dst, detail)

    def inspect(self, pkt):
        ts = float(getattr(pkt, "time", time.time()))
        if UDP in pkt and pkt[UDP].dport == self.disc_port and Raw in pkt:
            self._browse(pkt, ts)
        elif TCP in pkt and Raw in pkt:
            self._ipp(pkt, ts)

    def _browse(self, pkt, ts):
        src = pkt[IP].src if IP in pkt else "?"
        dst = pkt[IP].dst if IP in pkt else "?"
        raw = bytes(pkt[Raw].load)

        if len(raw) > 2048:
            self.alert(ts, "MALFORMED_BROWSE", "HIGH", src, dst,
                       f"oversized browse payload ({len(raw)} bytes)")
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            self.alert(ts, "MALFORMED_BROWSE", "HIGH", src, dst,
                       "non-ASCII bytes in browse payload")
            self._rate(src, dst, ts)
            return

        parsed = parse_browse(text)
        if parsed is None:
            self.alert(ts, "MALFORMED_BROWSE", "HIGH", src, dst,
                       f"unparseable browse data: {text[:60]!r}")
            self._rate(src, dst, ts)
            return

        host, port, queue = parsed
        if self.allow and host not in self.allow:
            self.alert(ts, "UNEXPECTED_PRINTER_HOST", "HIGH", src, dst,
                       f"advertises {host}:{port}/{queue} (host not allowlisted)")
        else:
            self.alert(ts, "UNAUTH_ADVERTISEMENT", "MEDIUM", src, dst,
                       f"browse advertises printer {host}:{port}/{queue}")

        if host != src and host not in ("localhost", "127.0.0.1"):
            self.alert(ts, "SOURCE_HOST_MISMATCH", "LOW", src, dst,
                       f"packet src {src} != advertised host {host} (possible spoof)")

        self._rate(src, dst, ts)

    def _rate(self, src, dst, ts):
        dq = self.recent[src]
        dq.append(ts)
        while dq and ts - dq[0] > self.window:
            dq.popleft()
        if len(dq) >= self.threshold and src not in self.flood_flagged:
            self.flood_flagged.add(src)
            self.alert(ts, "REPEATED_DISCOVERY", "HIGH", src, dst,
                       f"{len(dq)} browse packets within {self.window:.0f}s")

    def _ipp(self, pkt, ts):
        raw = bytes(pkt[Raw].load)
        if raw[:5] == b"POST " and b"application/ipp" in raw[:256]:
            src = pkt[IP].src if IP in pkt else "?"
            dst = pkt[IP].dst if IP in pkt else "?"
            dport = pkt[TCP].dport
            first = raw.split(b"\r\n", 1)[0].decode("ascii", "replace")
            self.alert(ts, "SUSPICIOUS_IPP", "MEDIUM", src, f"{dst}:{dport}",
                       f"victim IPP request: {first}")

    def summary(self):
        counts = defaultdict(int)
        for a in self.alerts:
            counts[a["category"]] += 1
        self.log.info("---- summary: %d alerts ----", len(self.alerts))
        for cat, n in sorted(counts.items()):
            self.log.info("  %-24s %d", cat, n)

    def export(self, csv_path=None, json_path=None):
        if json_path:
            with open(json_path, "w") as f:
                json.dump(self.alerts, f, indent=2)
            self.log.info("wrote %d alerts to %s", len(self.alerts), json_path)
        if csv_path:
            with open(csv_path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["time", "category", "severity",
                                                  "src", "dst", "detail"])
                w.writeheader()
                w.writerows(self.alerts)
            self.log.info("wrote %d alerts to %s", len(self.alerts), csv_path)


def main():
    ap = argparse.ArgumentParser(
        description="Detect suspicious CUPS printer-discovery / IPP activity.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="live-monitor this interface")
    src.add_argument("--pcap", help="analyse this capture file offline")
    ap.add_argument("--allow", action="append", default=[],
                    help="allowlisted printer host (repeatable); advertisements for "
                         "other hosts are flagged HIGH")
    ap.add_argument("--disc-port", type=int, default=631, help="discovery UDP port")
    ap.add_argument("--window", type=float, default=10.0,
                    help="flood detection window (seconds)")
    ap.add_argument("--threshold", type=int, default=10,
                    help="browse packets per window that trigger a flood alert")
    ap.add_argument("--filter", default="udp port 631 or tcp",
                    help="BPF filter for live capture")
    ap.add_argument("--csv", help="export alerts to this CSV file")
    ap.add_argument("--json", help="export alerts to this JSON file")
    ap.add_argument("--log", help="append log output to this file")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log:
        handlers.append(logging.FileHandler(args.log))
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s", handlers=handlers)
    log = logging.getLogger("cups_detector")

    det = Detector(allow=args.allow, window=args.window, threshold=args.threshold,
                   disc_port=args.disc_port, log=log)

    if args.pcap:
        log.info("analysing %s", args.pcap)
        with PcapReader(args.pcap) as pr:
            for pkt in pr:
                det.inspect(pkt)
    else:
        log.info("live monitoring on %s (filter: %s) - Ctrl-C to stop",
                 args.iface, args.filter)
        try:
            sniff(iface=args.iface, filter=args.filter, prn=det.inspect, store=False)
        except KeyboardInterrupt:
            log.info("stopped")

    det.summary()
    det.export(csv_path=args.csv, json_path=args.json)


if __name__ == "__main__":
    main()
