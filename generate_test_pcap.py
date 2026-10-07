from scapy.all import (
    Ether,
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    ICMP,
    wrpcap,
)
from datetime import datetime
import os


OUTPUT_FILE = "data/sample.pcap"


def build_test_capture():

    packets = []

    base_time = datetime.now().timestamp()

    # ========================================================
    # 1. NORMAL TCP TRAFFIC
    # ========================================================

    for i in range(30):

        packet = (
            Ether()
            / IP(
                src="192.168.1.10",
                dst="192.168.1.20",
            )
            / TCP(
                sport=40000 + i,
                dport=443,
            )
        )

        packet.time = base_time + i

        packets.append(packet)


    # ========================================================
    # 2. DNS TRAFFIC
    # ========================================================

    for i in range(20):

        packet = (
            Ether()
            / IP(
                src="192.168.1.10",
                dst="8.8.8.8",
            )
            / UDP(
                sport=50000 + i,
                dport=53,
            )
            / DNS(
                rd=1,
                qd=DNSQR(
                    qname="example.com"
                ),
            )
        )

        packet.time = base_time + 40 + i

        packets.append(packet)


    # ========================================================
    # 3. PORT SCAN
    # ========================================================

    scanner_ip = "192.168.1.50"

    for port in range(1, 151):

        packet = (
            Ether()
            / IP(
                src=scanner_ip,
                dst="192.168.1.100",
            )
            / TCP(
                sport=45000 + port,
                dport=port,
                flags="S",
            )
        )

        packet.time = base_time + 70 + port * 0.02

        packets.append(packet)


    # ========================================================
    # 4. SUSPICIOUS PORT ACTIVITY
    # ========================================================

    suspicious_ports = [
        21,
        23,
        445,
        3389,
        5900,
    ]

    for i, port in enumerate(
        suspicious_ports
    ):

        packet = (
            Ether()
            / IP(
                src="192.168.1.60",
                dst="192.168.1.100",
            )
            / TCP(
                sport=50000 + i,
                dport=port,
                flags="S",
            )
        )

        packet.time = base_time + 80 + i

        packets.append(packet)


    # ========================================================
    # 5. ICMP TRAFFIC
    # ========================================================

    for i in range(15):

        packet = (
            Ether()
            / IP(
                src="192.168.1.10",
                dst="192.168.1.1",
            )
            / ICMP()
        )

        packet.time = base_time + 90 + i

        packets.append(packet)


    # ========================================================
    # 6. HIGH REQUEST RATE
    # ========================================================

    for i in range(150):

        packet = (
            Ether()
            / IP(
                src="192.168.1.70",
                dst="192.168.1.100",
            )
            / TCP(
                sport=55000 + (i % 1000),
                dport=8080,
            )
        )

        packet.time = base_time + 100 + (i * 0.02)

        packets.append(packet)


    return packets


def main():

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True,
    )

    packets = build_test_capture()

    wrpcap(
        OUTPUT_FILE,
        packets,
    )

    print(
        f"Created test PCAP with "
        f"{len(packets)} packets."
    )

    print(
        f"Saved to: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()