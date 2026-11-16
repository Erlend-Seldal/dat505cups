# CUPS / cups-browsed Insecure Printer-Discovery — Attack & Detection Toolkit

Scapy-based tooling that investigates the 2024 CUPS `cups-browsed` printer-discovery
vulnerabilities (**CVE-2024-47176**, chained with CVE-2024-47076 / CVE-2024-47175 /
CVE-2024-47177) against an isolated Vulhub lab. The core flaw: `cups-browsed` listens
on **UDP/631** and accepts **unauthenticated** legacy "CUPS browse" packets, causing
the victim to initiate an outbound IPP connection to an attacker-specified host:port.

> **Ethics / scope:** For use only against the local, isolated Docker lab described
> below. Never target public, university, or third-party systems. Full RCE is *not*
> implemented — the tools demonstrate the insecure discovery mechanism only.

## Repository layout

```
.
├── cups_attack.py        # Scapy attack tool: craft/send browse packets, catch callback, export PCAP
├── cups_detector.py      # Scapy detection tool: live or offline, alerts to CSV/JSON
├── requirements.txt
├── README.md
├── pcap_files/           # captured traffic (normal + attack variants + mitigated)
└── evidence/             # detector CSV/JSON output + screenshots/logs
```

## Lab environment

| Role | Address | Port | Notes |
|------|---------|------|-------|
| Victim — cups-browsed 2.0.1 (Docker) | 172.18.0.2 | UDP/TCP 631 | Vulhub `cups-browsed/CVE-2024-47177`, image `vulhub/cups-browsed:2.0.1` |
| Attacker + virtual printer — Kali host | 172.18.0.1 | 6310 / 9100 | bridge gateway; `ippserver` as the legit printer |
| Capture interface | `br-8b2e9d48f6d5` | — | Docker bridge |

Vulnerable config observed: `BrowseRemoteProtocols dnssd cups` and
`BrowseOrder Deny,Allow` (accepts browse packets from any source, unauthenticated).

## Setup

```bash
sudo apt install -y docker.io docker-compose git python3-scapy wireshark tcpdump ippsample avahi-daemon
sudo systemctl enable --now avahi-daemon

git clone https://github.com/vulhub/vulhub.git
cd vulhub/cups-browsed/CVE-2024-47177
sudo docker compose up -d        # victim on 172.18.0.2:631
```

## Usage

### Attack tool

```bash
# advertise a rogue printer and catch the victim's callback
sudo python3 cups_attack.py --target 172.18.0.2 \
  --printer-host 172.18.0.1 --printer-port 9100 --name Evil \
  --iface br-8b2e9d48f6d5 --listen --pcap pcap_files/attack_basic.pcap -v
```

Key options: `--src` (spoof source IP), `--count`/`--interval` (flood),
`--raw` (send a malformed payload verbatim), `--listen` (catch callback),
`--pcap` (export capture), `--log` (log file).

### Detection tool

```bash
# offline analysis of a capture
python3 cups_detector.py --pcap pcap_files/attack_basic.pcap \
  --allow 172.18.0.1 --csv evidence/detect_attack.csv --json evidence/detect_attack.json

# live monitoring
sudo python3 cups_detector.py --iface br-8b2e9d48f6d5 --allow 172.18.0.1 \
  --csv evidence/live.csv
```

Alert categories: `UNAUTH_ADVERTISEMENT`, `UNEXPECTED_PRINTER_HOST`,
`SOURCE_HOST_MISMATCH`, `MALFORMED_BROWSE`, `REPEATED_DISCOVERY`, `SUSPICIOUS_IPP`.

## Mitigation demonstrated

Disable the legacy `cups` browse protocol in `cups-browsed.conf`
(`BrowseRemoteProtocols dnssd`) and restart the service. Before: advertisement +
3 IPP callbacks. After: advertisement still seen, **0 callbacks**. See the report
for the firewall caveat (Scapy's layer-2 injection bypasses the local `OUTPUT`
chain) and additional defence-in-depth measures.
