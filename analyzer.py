from scapy.all import (
    rdpcap,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    DNS
)

import pandas as pd


def load_packets(file_path):
    """
    Load packets from a PCAP or PCAPNG file.
    """
    return rdpcap(file_path)


def get_protocol(packet):
    """
    Identify the transport-layer protocol.
    """

    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    return "OTHER"


def get_application_protocol(packet):
    """
    Identify application-level protocols
    carried inside transport protocols.
    """

    if packet.haslayer(DNS):
        return "DNS"

    return "OTHER"


def get_ip_addresses(packet):
    """
    Extract source and destination IP addresses.
    Supports IPv4 and IPv6.
    """

    if packet.haslayer(IP):

        return (
            packet[IP].src,
            packet[IP].dst
        )

    if packet.haslayer(IPv6):

        return (
            packet[IPv6].src,
            packet[IPv6].dst
        )

    return None, None


def get_ports(packet):
    """
    Extract source and destination ports.
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
    Convert packets into a pandas DataFrame.
    """

    records = []

    for packet in packets:

        source_ip, destination_ip = get_ip_addresses(packet)

        source_port, destination_port = get_ports(packet)

        transport_protocol = get_protocol(packet)

        application_protocol = get_application_protocol(packet)

        packet_size = len(packet)

        timestamp = float(packet.time)

        records.append({

            "timestamp": timestamp,

            "source_ip": source_ip,

            "destination_ip": destination_ip,

            "source_port": source_port,

            "destination_port": destination_port,

            "protocol": transport_protocol,

            "application_protocol": application_protocol,

            "packet_size": packet_size

        })

    return pd.DataFrame(records)


def protocol_statistics(df):
    """
    Calculate protocol counts and percentages.
    """

    counts = df["protocol"].value_counts()

    percentages = (
        df["protocol"]
        .value_counts(normalize=True)
        .mul(100)
        .round(2)
    )

    result = pd.DataFrame({

        "packets": counts,

        "percentage": percentages

    })

    return result


def top_source_ips(df, limit=10):
    """
    Return the most active source IP addresses.
    """

    result = (
        df["source_ip"]
        .value_counts()
        .head(limit)
        .reset_index()
    )

    result.columns = [
        "ip",
        "packets"
    ]

    return result


def top_destination_ips(df, limit=10):
    """
    Return the most active destination IP addresses.
    """

    result = (
        df["destination_ip"]
        .value_counts()
        .head(limit)
        .reset_index()
    )

    result.columns = [
        "ip",
        "packets"
    ]

    return result


def top_destination_ports(df, limit=10):
    """
    Return the most frequently contacted destination ports.
    """

    ports = (
        df["destination_port"]
        .dropna()
    )

    result = (
        ports
        .value_counts()
        .head(limit)
        .reset_index()
    )

    result.columns = [
        "port",
        "packets"
    ]

    return result


def packet_statistics(df):
    """
    Calculate general packet statistics.
    """

    return {

        "total_packets": len(df),

        "average_packet_size": round(
            df["packet_size"].mean(),
            2
        ),

        "maximum_packet_size": int(
            df["packet_size"].max()
        ),

        "minimum_packet_size": int(
            df["packet_size"].min()
        )

    }