import pandas as pd


# Ports that we want to monitor
# These ports are not automatically malicious.
# They are simply interesting from a security-monitoring perspective.

SUSPICIOUS_PORTS = {

    21: "FTP",

    23: "Telnet",

    445: "SMB",

    3389: "RDP",

    5900: "VNC"

}


def detect_port_scans(
    df,
    port_threshold=100
):
    """
    Detect possible port scanning.

    A source IP is flagged when it contacts
    at least 100 unique destination ports.
    """

    alerts = []

    traffic = df[
        df["destination_port"].notna()
    ]

    grouped = (
        traffic
        .groupby("source_ip")["destination_port"]
        .nunique()
    )

    for source_ip, unique_ports in grouped.items():

        if unique_ports >= port_threshold:

            alerts.append({

                "type": "Port Scan",

                "severity": "HIGH",

                "source_ip": source_ip,

                "description": (
                    f"{source_ip} contacted "
                    f"{unique_ports} unique ports"
                )

            })

    return alerts


def detect_high_request_rate(
    df,
    packet_threshold=100
):
    """
    Detect a high number of packets
    from one source IP within a 10-second window.
    """

    alerts = []

    if df.empty:

        return alerts

    working_df = df.copy()

    working_df["time_window"] = (
        working_df["timestamp"] // 10
    )

    grouped = (
        working_df
        .groupby(
            [
                "source_ip",
                "time_window"
            ]
        )
        .size()
        .reset_index(
            name="packet_count"
        )
    )

    for _, row in grouped.iterrows():

        if row["packet_count"] >= packet_threshold:

            alerts.append({

                "type": "High Request Rate",

                "severity": "MEDIUM",

                "source_ip": row["source_ip"],

                "description": (
                    f"{int(row['packet_count'])} "
                    f"packets detected within "
                    f"a 10-second window"
                )

            })

    return alerts


def detect_suspicious_ports(df):
    """
    Detect traffic involving selected
    commonly monitored ports.
    """

    alerts = []

    traffic = df[
        df["destination_port"].isin(
            SUSPICIOUS_PORTS.keys()
        )
    ]

    grouped = (
        traffic
        .groupby(
            [
                "source_ip",
                "destination_port"
            ]
        )
        .size()
        .reset_index(
            name="packet_count"
        )
    )

    for _, row in grouped.iterrows():

        port = int(
            row["destination_port"]
        )

        service = SUSPICIOUS_PORTS[port]

        alerts.append({

            "type": "Suspicious Port Activity",

            "severity": "LOW",

            "source_ip": row["source_ip"],

            "description": (
                f"Traffic detected toward "
                f"port {port} ({service})"
            )

        })

    return alerts


def run_anomaly_detection(df):
    """
    Run all anomaly detection rules.
    """

    alerts = []

    alerts.extend(
        detect_port_scans(df)
    )

    alerts.extend(
        detect_high_request_rate(df)
    )

    alerts.extend(
        detect_suspicious_ports(df)
    )

    return pd.DataFrame(alerts)