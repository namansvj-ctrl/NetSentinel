from scapy.all import (
    rdpcap,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
)
import pandas as pd


def load_packets(file_path):
    """
    Load all packets from a PCAP or PCAPNG file.

    Returns:
        Scapy PacketList containing every successfully read packet.
    """
    packets = rdpcap(file_path)
    return packets


def get_protocol(packet):
    """
    Determine the primary network/transport protocol.
    """

    if packet.haslayer(ARP):
        return "ARP"

    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(IPv6):
        return "IPv6"

    if packet.haslayer(IP):
        return "IP"

    return "Other"


def get_application_protocol(packet):
    """
    Identify common application-layer protocols.
    """

    if packet.haslayer(DNS):
        return "DNS"

    return ""


def get_ip_addresses(packet):
    """
    Extract source and destination addresses from IPv4, IPv6 or ARP.
    """

    source_ip = None
    destination_ip = None

    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    elif packet.haslayer(IPv6):
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    elif packet.haslayer(ARP):
        source_ip = packet[ARP].psrc
        destination_ip = packet[ARP].pdst

    return source_ip, destination_ip


def get_ports(packet):
    """
    Extract source and destination ports when available.
    """

    source_port = None
    destination_port = None

    if packet.haslayer(TCP):
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    return source_port, destination_port


def analyze_packets(packets):
    """
    Convert every packet into a structured Pandas DataFrame.

    IMPORTANT:
    This function does NOT drop non-IP packets.

    Therefore:
        len(packets) == len(result_dataframe)

    whenever every packet can be represented successfully.
    """

    rows = []

    for index, packet in enumerate(packets):

        try:
            source_ip, destination_ip = get_ip_addresses(packet)
            source_port, destination_port = get_ports(packet)

            protocol = get_protocol(packet)
            application_protocol = get_application_protocol(packet)

            timestamp = float(packet.time)

            packet_size = len(packet)

            rows.append(
                {
                    "packet_number": index + 1,
                    "timestamp": timestamp,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "source_port": source_port,
                    "destination_port": destination_port,
                    "protocol": protocol,
                    "application_protocol": application_protocol,
                    "packet_size": packet_size,
                }
            )

        except Exception:
            # Even if a strange packet cannot be fully decoded,
            # preserve it in the analysis table.
            rows.append(
                {
                    "packet_number": index + 1,
                    "timestamp": None,
                    "source_ip": None,
                    "destination_ip": None,
                    "source_port": None,
                    "destination_port": None,
                    "protocol": "Other",
                    "application_protocol": "",
                    "packet_size": len(packet),
                }
            )

    df = pd.DataFrame(rows)

    if df.empty:
        return df

    # Convert timestamps to readable datetime values
    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        unit="s",
        errors="coerce",
    )

    # Numeric columns
    df["source_port"] = pd.to_numeric(
        df["source_port"],
        errors="coerce",
    )

    df["destination_port"] = pd.to_numeric(
        df["destination_port"],
        errors="coerce",
    )

    df["packet_size"] = pd.to_numeric(
        df["packet_size"],
        errors="coerce",
    )

    return df