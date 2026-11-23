import time
import subprocess
from collections import defaultdict
from scapy.all import sniff, IP, TCP, Raw


class RuleEngine:
    def __init__(self):
        self.blocked_ips = set()
        self.port_scan_tracker = defaultdict(set)

        # Define known malicious payloads
        self.sql_signatures = [
            b"UNION SELECT",
            b"OR 1=1",
            b"DROP TABLE"
        ]

    def log_incident(self, src_ip, rule_name):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] ALERT: {rule_name} triggered by {src_ip}\n"

        with open("ips_incident.log", "a") as log_file:
            log_file.write(log_entry)

        print(log_entry.strip())

    def analyze(self, packet):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if src_ip in self.blocked_ips:
            return

        # Rule 1: Telnet Traffic
        if dst_port == 23:
            self.log_incident(src_ip, "Telnet Traffic (Port 23)")
            self.trigger_block(src_ip)
            return

        # Rule 2: Port Scan Detection
        self.port_scan_tracker[src_ip].add(dst_port)

        if len(self.port_scan_tracker[src_ip]) > 10:
            self.log_incident(
                src_ip,
                "Port Scan Detected (>10 ports)"
            )
            self.trigger_block(src_ip)
            return

        # Rule 3: Deep Packet Inspection (SQL Injection)
        if packet.haslayer(Raw):
            # Extract the raw payload and convert to uppercase for matching
            payload = packet[Raw].load.upper()

            for sig in self.sql_signatures:
                if sig in payload:
                    self.log_incident(
                        src_ip,
                        f"SQL Injection Attempt ({sig.decode()})"
                    )
                    self.trigger_block(src_ip)
                    return

    def trigger_block(self, ip_address):
        print(
            f"[X] ACTION: Executing REAL firewall block for {ip_address}"
        )

        self.blocked_ips.add(ip_address)

        try:
            subprocess.run(
                [
                    "iptables",
                    "-A",
                    "INPUT",
                    "-s",
                    ip_address,
                    "-j",
                    "DROP"
                ],
                check=True
            )

            print(
                f"[+] iptables updated: "
                f"Dropping all future packets from {ip_address}"
            )

        except subprocess.CalledProcessError as e:
            print(f"[-] Failed to update iptables: {e}")


class PacketSniffer:
    def __init__(self):
        self.engine = RuleEngine()

    def start(self):
        print(
            "[*] Starting IPS Sniffer with "
            "Deep Packet Inspection (Layer 7)..."
        )

        sniff(
            iface="lo",
            prn=self.process_packet,
            store=False
        )

    def process_packet(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            self.engine.analyze(packet)


if __name__ == "__main__":
    ips = PacketSniffer()
    ips.start()