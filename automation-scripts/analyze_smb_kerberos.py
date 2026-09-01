import sys
import os
import json
import subprocess
import argparse
from scapy.all import rdpcap, IP, TCP

def run_tshark(pcap_file, display_filter, fields):
    """Executes tshark with specified filters and returns line outputs."""
    cmd = ["tshark", "-r", pcap_file, "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd.extend(["-e", f])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lines = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        return lines
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

def scan_raw_payloads(pcap_file):
    """Scapy engine to scan packet payloads for SMB & NTLM indicators."""
    alerts = []
    try:
        packets = rdpcap(pcap_file)
    except Exception:
        return alerts

    for idx, pkt in enumerate(packets, start=1):
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            raw_bytes = bytes(pkt[TCP].payload) if pkt[TCP].payload else bytes(pkt)
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # 1. Admin Share Match
            if any(share in raw_bytes for share in [b"C$\x00", b"ADMIN$\x00", b"IPC$\x00", b"C$", b"ADMIN$", b"IPC$"]):
                alerts.append({
                    "packet": str(idx),
                    "type": "SMB2 Admin Share Access",
                    "severity": "HIGH",
                    "src": src_ip,
                    "dst": dst_ip,
                    "details": "Payload match identified administrative share indicator (C$/ADMIN$/IPC$)"
                })

            # 2. Named Pipe / PsExec Match
            if any(pipe in raw_bytes for pipe in [b"svcctl", b"PSEXESVC"]):
                alerts.append({
                    "packet": str(idx),
                    "type": "PsExec / Service Control Pipe Execution",
                    "severity": "CRITICAL",
                    "src": src_ip,
                    "dst": dst_ip,
                    "details": "Identified PsExec/Service Control Manager named pipe interaction (svcctl/PSEXESVC)"
                })

            # 3. NTLMSSP Authentication / Downgrade Hazard
            if b"NTLMSSP" in raw_bytes:
                alerts.append({
                    "packet": str(idx),
                    "type": "NTLM Authentication Over SMB (Downgrade Hazard)",
                    "severity": "HIGH",
                    "src": src_ip,
                    "dst": dst_ip,
                    "details": "Identified NTLMSSP exchange over SMB. Potential NTLM Relay or credential harvesting vector."
                })

    return alerts

def analyze_pcap(pcap_file):
    alerts = []
    seen_keys = set()

    # 1. TShark Query: SMB2 Admin Share Access
    tshark_shares = run_tshark(
        pcap_file,
        'smb2.tree.name contains "C$" or smb2.tree.name contains "ADMIN$" or smb2.tree.name contains "IPC$"',
        ["frame.number", "ip.src", "ip.dst", "smb2.tree.name"]
    )
    for line in tshark_shares:
        parts = line.split("\t")
        if len(parts) >= 3 and parts[1] and parts[2]:
            key = (parts[0], "SMB2 Admin Share Access")
            seen_keys.add(key)
            alerts.append({
                "packet": parts[0],
                "type": "SMB2 Admin Share Access",
                "severity": "HIGH",
                "src": parts[1],
                "dst": parts[2],
                "details": f"Accessed administrative share: {parts[3] if len(parts) > 3 and parts[3] else 'C$/ADMIN$/IPC$'}"
            })

    # 2. TShark Query: NTLMSSP Authentication over SMB
    tshark_ntlm = run_tshark(
        pcap_file,
        'ntlmssp or frame contains "NTLMSSP"',
        ["frame.number", "ip.src", "ip.dst"]
    )
    for line in tshark_ntlm:
        parts = line.split("\t")
        if len(parts) >= 3 and parts[1] and parts[2]:
            key = (parts[0], "NTLM Authentication Over SMB (Downgrade Hazard)")
            seen_keys.add(key)
            alerts.append({
                "packet": parts[0],
                "type": "NTLM Authentication Over SMB (Downgrade Hazard)",
                "severity": "HIGH",
                "src": parts[1],
                "dst": parts[2],
                "details": "Identified NTLMSSP exchange over SMB via TShark protocol dissection."
            })

    # 3. Always run Scapy payload scan to catch raw stream hits
    scapy_alerts = scan_raw_payloads(pcap_file)
    for sa in scapy_alerts:
        key = (sa["packet"], sa["type"])
        if key not in seen_keys:
            seen_keys.add(key)
            alerts.append(sa)

    return alerts

def main():
    parser = argparse.ArgumentParser(description="SMB2 & Kerberos Threat Hunting Analyzer")
    parser.add_argument("pcap", help="Path to PCAP file")
    parser.add_argument("--json", help="Path to save JSON alert output", default=None)
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"[-] Error: File {args.pcap} not found.")
        sys.exit(1)

    print("=" * 70)
    print(f"[*] Starting Threat Hunting Analysis: {args.pcap}")
    print("=" * 70)

    alerts = analyze_pcap(args.pcap)

    print(f"\n[✔] Processed SMB2 & Kerberos activity.")
    print(f"[✔] Total Security Alerts Identified: {len(alerts)}\n")

    if alerts:
        print(f"{'PKT #':<8} | {'SEVERITY':<10} | {'ALERT TYPE':<40} | {'SRC IP':<15} -> {'DST IP'}")
        print("-" * 100)
        for a in alerts:
            print(f"{a['packet']:<8} | {a['severity']:<10} | {a['type']:<40} | {a['src']:<15} -> {a['dst']}")
            print(f"         └─ Details: {a['details']}\n")
    else:
        print("[*] No suspicious SMB2 or Kerberos anomalies detected.")

    if args.json:
        output_data = {
            "pcap": args.pcap,
            "alert_count": len(alerts),
            "alerts": alerts
        }
        with open(args.json, "w") as f:
            json.dump(output_data, f, indent=4)
        print(f"[+] Successfully exported SIEM-ready JSON output to: {args.json}")

if __name__ == "__main__":
    main()