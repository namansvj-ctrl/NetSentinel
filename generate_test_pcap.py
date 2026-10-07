from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap


packets = []


# ---------------------------------------
# 1. Normal HTTPS-like TCP traffic
# ---------------------------------------

for i in range(30):

    packet = (
        IP(
            src="192.168.1.10",
            dst="93.184.216.34"
        )
        /
        TCP(
            sport=5000 + i,
            dport=443
        )
    )

    packets.append(packet)


# ---------------------------------------
# 2. DNS traffic
# ---------------------------------------

for i in range(20):

    packet = (
        IP(
            src="192.168.1.10",
            dst="8.8.8.8"
        )
        /
        UDP(
            sport=4000 + i,
            dport=53
        )
        /
        DNS(
            rd=1,
            qd=DNSQR(
                qname="example.com"
            )
        )
    )

    packets.append(packet)


# ---------------------------------------
# 3. ICMP traffic
# ---------------------------------------

for i in range(10):

    packet = (
        IP(
            src="192.168.1.10",
            dst="8.8.8.8"
        )
        /
        ICMP()
    )

    packets.append(packet)


# ---------------------------------------
# 4. Simulated port scan
# ---------------------------------------

for port in range(1, 151):

    packet = (
        IP(
            src="192.168.1.50",
            dst="192.168.1.10"
        )
        /
        TCP(
            sport=6000,
            dport=port,
            flags="S"
        )
    )

    packets.append(packet)


# ---------------------------------------
# 5. Suspicious RDP traffic
# ---------------------------------------

for i in range(10):

    packet = (
        IP(
            src="192.168.1.60",
            dst="192.168.1.10"
        )
        /
        TCP(
            sport=7000 + i,
            dport=3389
        )
    )

    packets.append(packet)


# ---------------------------------------
# 6. Save the PCAP
# ---------------------------------------

wrpcap(
    "data/sample.pcap",
    packets
)


print(
    f"Created test PCAP with {len(packets)} packets."
)