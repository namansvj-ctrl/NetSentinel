import streamlit as st
import pandas as pd
import plotly.express as px
import tempfile
import os

from analyzer import (
    load_packets,
    analyze_packets,
    protocol_statistics,
    top_source_ips,
    top_destination_ips,
    top_destination_ports,
    packet_statistics
)

from anomaly_detector import run_anomaly_detection


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="NetSentinel",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# HEADER
# =========================================================

st.title("🛡️ NetSentinel")

st.subheader(
    "Network Traffic Analyzer & Anomaly Detection System"
)

st.write(
    "Analyze network packet captures, identify traffic patterns, "
    "and detect potentially suspicious activity."
)


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.title("📁 Traffic Analysis")

uploaded_file = st.sidebar.file_uploader(
    "Upload a PCAP / PCAPNG file",
    type=["pcap", "pcapng"]
)


# =========================================================
# WAIT FOR PCAP
# =========================================================

if uploaded_file is None:

    st.info(
        "👈 Upload a PCAP or PCAPNG file from the sidebar "
        "to begin analysis."
    )

    st.markdown("---")

    st.markdown("## 🔍 NetSentinel Features")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(
            """
            ### 🌐 Traffic Analysis

            - TCP
            - UDP
            - ICMP
            - DNS
            - Packet sizes
            """
        )

    with col2:
        st.markdown(
            """
            ### 💻 Network Intelligence

            - Top source IPs
            - Top destination IPs
            - Top ports
            - Traffic statistics
            """
        )

    with col3:
        st.markdown(
            """
            ### 🚨 Security Detection

            - Port scans
            - High request rates
            - Suspicious ports
            - Severity alerts
            """
        )

    st.stop()


# =========================================================
# SAVE UPLOADED PCAP TEMPORARILY
# =========================================================

file_extension = os.path.splitext(
    uploaded_file.name
)[1]

with tempfile.NamedTemporaryFile(
    delete=False,
    suffix=file_extension
) as temp_file:

    temp_file.write(
        uploaded_file.getbuffer()
    )

    temp_path = temp_file.name


# =========================================================
# LOAD AND ANALYZE PACKETS
# =========================================================

try:

    packets = load_packets(temp_path)

    df = analyze_packets(packets)

except Exception as error:

    st.error(
        f"❌ Could not analyze the capture file: {error}"
    )

    os.remove(temp_path)

    st.stop()


os.remove(temp_path)


# =========================================================
# VALIDATE DATA
# =========================================================

if df.empty:

    st.warning(
        "The capture file does not contain analyzable packets."
    )

    st.stop()


df = df.dropna(
    subset=["source_ip", "destination_ip"]
)


# =========================================================
# CALCULATE STATISTICS
# =========================================================

stats = packet_statistics(df)

protocols = protocol_statistics(df)

alerts = run_anomaly_detection(df)


# =========================================================
# TOP METRICS
# =========================================================

st.markdown("---")

st.subheader("📊 Network Overview")

col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "Total Packets",
        f"{stats['total_packets']:,}"
    )


with col2:

    tcp_percentage = (
        protocols.loc["TCP", "percentage"]
        if "TCP" in protocols.index
        else 0
    )

    st.metric(
        "TCP Traffic",
        f"{tcp_percentage}%"
    )


with col3:

    udp_percentage = (
        protocols.loc["UDP", "percentage"]
        if "UDP" in protocols.index
        else 0
    )

    st.metric(
        "UDP Traffic",
        f"{udp_percentage}%"
    )


with col4:

    st.metric(
        "Security Alerts",
        len(alerts)
    )


# =========================================================
# PACKET STATISTICS
# =========================================================

st.markdown("---")

st.subheader("📦 Packet Statistics")

col1, col2, col3 = st.columns(3)


with col1:

    st.metric(
        "Average Packet Size",
        f"{stats['average_packet_size']} bytes"
    )


with col2:

    st.metric(
        "Largest Packet",
        f"{stats['maximum_packet_size']} bytes"
    )


with col3:

    st.metric(
        "Smallest Packet",
        f"{stats['minimum_packet_size']} bytes"
    )


# =========================================================
# PROTOCOL DISTRIBUTION
# =========================================================

st.markdown("---")

st.subheader("🌐 Protocol Distribution")

protocol_chart_data = (
    protocols
    .reset_index()
    .rename(
        columns={
            "index": "protocol"
        }
    )
)

fig_protocol = px.pie(
    protocol_chart_data,
    names="protocol",
    values="packets",
    hole=0.45,
    title="Network Protocol Distribution"
)

st.plotly_chart(
    fig_protocol,
    use_container_width=True
)


# =========================================================
# TOP TALKERS
# =========================================================

st.markdown("---")

st.subheader("💻 Top Network Talkers")

source_data = top_source_ips(df)

destination_data = top_destination_ips(df)

col1, col2 = st.columns(2)


with col1:

    fig_source = px.bar(
        source_data,
        x="ip",
        y="packets",
        title="Top Source IPs",
        labels={
            "ip": "Source IP",
            "packets": "Packets"
        }
    )

    st.plotly_chart(
        fig_source,
        use_container_width=True
    )


with col2:

    fig_destination = px.bar(
        destination_data,
        x="ip",
        y="packets",
        title="Top Destination IPs",
        labels={
            "ip": "Destination IP",
            "packets": "Packets"
        }
    )

    st.plotly_chart(
        fig_destination,
        use_container_width=True
    )


# =========================================================
# TOP PORTS
# =========================================================

st.markdown("---")

st.subheader("🔌 Most Frequently Contacted Ports")

port_data = top_destination_ports(df)

fig_ports = px.bar(
    port_data,
    x="port",
    y="packets",
    title="Top Destination Ports",
    labels={
        "port": "Destination Port",
        "packets": "Packets"
    }
)

st.plotly_chart(
    fig_ports,
    use_container_width=True
)


# =========================================================
# SECURITY ALERTS
# =========================================================

st.markdown("---")

st.subheader("🚨 Security Alerts")


if alerts.empty:

    st.success(
        "✅ No suspicious activity was detected "
        "using the configured detection rules."
    )

else:

    for _, alert in alerts.iterrows():

        severity = alert["severity"]

        if severity == "HIGH":

            st.error(
                f"🔴 HIGH — {alert['type']}\n\n"
                f"{alert['description']}"
            )

        elif severity == "MEDIUM":

            st.warning(
                f"🟠 MEDIUM — {alert['type']}\n\n"
                f"{alert['description']}"
            )

        else:

            st.info(
                f"🟡 LOW — {alert['type']}\n\n"
                f"{alert['description']}"
            )


# =========================================================
# ALERT TABLE
# =========================================================

if not alerts.empty:

    st.subheader("📋 Alert Details")

    st.dataframe(
        alerts,
        use_container_width=True,
        hide_index=True
    )


# =========================================================
# RAW PACKET DATA
# =========================================================

st.markdown("---")

with st.expander("🔎 View Parsed Packet Data"):

    st.dataframe(
        df.head(500),
        use_container_width=True,
        hide_index=True
    )


# =========================================================
# EXPORT
# =========================================================

st.markdown("---")

st.subheader("📥 Export Analysis")

csv_data = df.to_csv(
    index=False
).encode("utf-8")

st.download_button(
    label="Download Packet Analysis CSV",
    data=csv_data,
    file_name="netsentinel_packet_analysis.csv",
    mime="text/csv"
)


# =========================================================
# FOOTER
# =========================================================

st.markdown("---")

st.caption(
    "NetSentinel | Network Traffic Analyzer & "
    "Anomaly Detection System | Hackathon PS9"
)