import pandas as pd


# Ports that are commonly monitored during security analysis.
SUSPICIOUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
}


def detect_port_scans(
    df,
    unique_port_threshold=20,
):
    """
    Detect hosts contacting an unusually large number
    of destination ports.
    """

    alerts = []

    if df.empty:
        return alerts

    scan_df = df[
        df["source_ip"].notna()
        & df["destination_port"].notna()
    ].copy()

    if scan_df.empty:
        return alerts

    grouped = (
        scan_df.groupby("source_ip")["destination_port"]
        .nunique()
        .reset_index(name="unique_ports")
    )

    suspicious = grouped[
        grouped["unique_ports"] >= unique_port_threshold
    ]

    for _, row in suspicious.iterrows():

        severity = "HIGH"

        alerts.append(
            {
                "severity": severity,
                "alert_type": "Port Scan",
                "source_ip": row["source_ip"],
                "destination_ip": "Multiple",
                "details": (
                    f"{int(row['unique_ports'])} unique destination "
                    f"ports contacted"
                ),
            }
        )

    return alerts


def detect_high_request_rates(
    df,
    packet_threshold=100,
    window_seconds=10,
):
    """
    Detect unusually high packet/request rates.

    The capture is grouped into time windows for each source IP.
    """

    alerts = []

    if df.empty:
        return alerts

    rate_df = df[
        df["source_ip"].notna()
        & df["timestamp"].notna()
    ].copy()

    if rate_df.empty:
        return alerts

    rate_df = rate_df.sort_values("timestamp")

    for source_ip, group in rate_df.groupby("source_ip"):

        group = group.sort_values("timestamp").copy()

        timestamps = group["timestamp"]

        start_time = timestamps.iloc[0]

        while start_time <= timestamps.iloc[-1]:

            end_time = start_time + pd.Timedelta(
                seconds=window_seconds
            )

            window = group[
                (group["timestamp"] >= start_time)
                & (group["timestamp"] < end_time)
            ]

            count = len(window)

            if count >= packet_threshold:

                alerts.append(
                    {
                        "severity": "MEDIUM",
                        "alert_type": "High Request Rate",
                        "source_ip": source_ip,
                        "destination_ip": "Multiple",
                        "details": (
                            f"{count} packets detected within "
                            f"{window_seconds} seconds"
                        ),
                    }
                )

                # Avoid generating many overlapping alerts
                # for the same source.
                break

            start_time = start_time + pd.Timedelta(seconds=1)

    return alerts


def detect_suspicious_ports(df):
    """
    Detect traffic involving commonly monitored ports.
    """

    alerts = []

    if df.empty:
        return alerts

    port_df = df[
        df["destination_port"].notna()
    ].copy()

    if port_df.empty:
        return alerts

    port_df["destination_port"] = pd.to_numeric(
        port_df["destination_port"],
        errors="coerce",
    )

    port_df = port_df.dropna(
        subset=["destination_port"]
    )

    port_df["destination_port"] = (
        port_df["destination_port"].astype(int)
    )

    suspicious = port_df[
        port_df["destination_port"].isin(
            SUSPICIOUS_PORTS.keys()
        )
    ]

    if suspicious.empty:
        return alerts

    grouped = suspicious.groupby(
        ["source_ip", "destination_ip", "destination_port"]
    ).size().reset_index(name="packets")

    for _, row in grouped.iterrows():

        port = int(row["destination_port"])

        service = SUSPICIOUS_PORTS.get(
            port,
            "Unknown",
        )

        alerts.append(
            {
                "severity": "LOW",
                "alert_type": "Suspicious Port Activity",
                "source_ip": row["source_ip"],
                "destination_ip": row["destination_ip"],
                "details": (
                    f"Traffic to port {port} ({service}) — "
                    f"{int(row['packets'])} packets"
                ),
            }
        )

    return alerts


def detect_anomalies(df):
    """
    Run all anomaly detection rules.
    """

    if df is None or df.empty:
        return pd.DataFrame(
            columns=[
                "severity",
                "alert_type",
                "source_ip",
                "destination_ip",
                "details",
            ]
        )

    alerts = []

    alerts.extend(
        detect_port_scans(df)
    )

    alerts.extend(
        detect_high_request_rates(df)
    )

    alerts.extend(
        detect_suspicious_ports(df)
    )

    alerts_df = pd.DataFrame(alerts)

    if alerts_df.empty:
        return pd.DataFrame(
            columns=[
                "severity",
                "alert_type",
                "source_ip",
                "destination_ip",
                "details",
            ]
        )

    severity_order = {
        "HIGH": 0,
        "MEDIUM": 1,
        "LOW": 2,
    }

    alerts_df["_severity_order"] = (
        alerts_df["severity"]
        .map(severity_order)
        .fillna(99)
    )

    alerts_df = (
        alerts_df
        .sort_values("_severity_order")
        .drop(columns="_severity_order")
        .reset_index(drop=True)
    )

    return alerts_df