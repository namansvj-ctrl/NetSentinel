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
    packet_statistics,
)

from anomaly_detector import run_anomaly_detection


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="NetSentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# PROFESSIONAL DARK THEME
# ============================================================

st.markdown(
    """
<style>

.stApp {
    background-color: #0b0f14;
    color: #e8edf3;
}

.main .block-container {
    max-width: 1450px;
    padding-top: 2rem;
    padding-bottom: 4rem;
}

section[data-testid="stSidebar"] {
    background-color: #0f141b;
    border-right: 1px solid #202832;
}

div[data-testid="stMetric"] {
    background-color: #11171f;
    border: 1px solid #222c37;
    border-radius: 14px;
    padding: 18px;
}

div[data-testid="stMetricLabel"] {
    color: #8793a1;
}

div[data-testid="stMetricValue"] {
    color: #f4f7fa;
}

div[data-testid="stDataFrame"] {
    border: 1px solid #222c37;
    border-radius: 12px;
    overflow: hidden;
}

button[data-baseweb="tab"] {
    font-weight: 600;
}

.net-status {
    display: inline-block;
    padding: 6px 11px;
    border-radius: 999px;
    background: #101b18;
    border: 1px solid #1f4034;
    color: #8ce1bd;
    font-size: 12px;
    font-weight: 600;
}

</style>
""",
    unsafe_allow_html=True,
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.title("NetSentinel")

    st.caption("Network Security Intelligence")

    st.divider()

    st.subheader("PCAP Analysis")

    uploaded_file = st.file_uploader(
        "Upload a PCAP / PCAPNG file",
        type=["pcap", "pcapng"],
    )

    st.caption(
        "Upload a network capture to analyze packet behavior, "
        "traffic patterns and potential security anomalies."
    )


# ============================================================
# LANDING PAGE
# ============================================================

if uploaded_file is None:

    st.title("🛡️ NetSentinel")

    st.subheader(
        "Network Traffic Analyzer & Anomaly Detection"
    )

    st.markdown(
        '<span class="net-status">● SYSTEM READY</span>',
        unsafe_allow_html=True,
    )

    st.divider()

    st.info(
        "Upload a PCAP or PCAPNG file from the sidebar "
        "to begin analysis."
    )

    st.markdown("### What NetSentinel analyzes")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Traffic Analysis",
            "Ready",
        )
        st.caption(
            "Protocols, IPs, ports and packet statistics"
        )

    with col2:
        st.metric(
            "Anomaly Detection",
            "Enabled",
        )
        st.caption(
            "Suspicious traffic patterns and security alerts"
        )

    with col3:
        st.metric(
            "Export",
            "CSV",
        )
        st.caption(
            "Download analyzed packet information"
        )

    st.stop()


# ============================================================
# SAVE UPLOADED PCAP TEMPORARILY
# ============================================================

file_extension = os.path.splitext(
    uploaded_file.name
)[1]

with tempfile.NamedTemporaryFile(
    delete=False,
    suffix=file_extension,
) as temp_file:

    temp_file.write(
        uploaded_file.getbuffer()
    )

    temp_path = temp_file.name


# ============================================================
# LOAD PCAP
# ============================================================

try:

    # Load the COMPLETE packet capture
    packets = load_packets(temp_path)

    # TRUE number of packets physically inside
    # the uploaded PCAP/PCAPNG
    total_capture_packets = len(packets)

    # Convert packets to the analysis dataframe
    df = analyze_packets(packets)

except Exception as error:

    st.error(
        f"Unable to analyze the capture: {error}"
    )

    try:
        os.remove(temp_path)
    except OSError:
        pass

    st.stop()


# Remove temporary file
try:
    os.remove(temp_path)
except OSError:
    pass


# ============================================================
# CHECK DATA
# ============================================================

if df.empty:

    st.warning(
        "No analyzable packets were found in this capture."
    )

    st.stop()


# ============================================================
# PACKET COUNTS
# ============================================================

# Number of packets converted by analyzer.py
analyzable_packets = len(df)


# Current security engine works with packets that have
# both source and destination IP addresses.
df = df.dropna(
    subset=[
        "source_ip",
        "destination_ip",
    ]
)


# Number of packets actually used by the current
# IP-based traffic/security analysis
ip_analyzable_packets = len(df)


# ============================================================
# ANALYSIS
# ============================================================

stats = packet_statistics(df)

protocols = protocol_statistics(df)

alerts = run_anomaly_detection(df)


# ============================================================
# ALERT COUNTS
# ============================================================

if alerts.empty:

    high_alerts = 0
    medium_alerts = 0
    low_alerts = 0

else:

    high_alerts = int(
        (
            alerts["severity"] == "HIGH"
        ).sum()
    )

    medium_alerts = int(
        (
            alerts["severity"] == "MEDIUM"
        ).sum()
    )

    low_alerts = int(
        (
            alerts["severity"] == "LOW"
        ).sum()
    )


# ============================================================
# TCP / UDP PERCENTAGES
# ============================================================

tcp_percentage = (
    float(
        protocols.loc[
            "TCP",
            "percentage"
        ]
    )
    if "TCP" in protocols.index
    else 0
)

udp_percentage = (
    float(
        protocols.loc[
            "UDP",
            "percentage"
        ]
    )
    if "UDP" in protocols.index
    else 0
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ NetSentinel")

st.subheader(
    "Network Traffic Analyzer & Anomaly Detection"
)

st.markdown(
    '<span class="net-status">● ANALYSIS COMPLETE</span>',
    unsafe_allow_html=True,
)

st.caption(
    f"Capture: **{uploaded_file.name}** · "
    f"**{total_capture_packets:,} total packets** · "
    f"**{ip_analyzable_packets:,} analyzed packets** · "
    f"**{len(alerts)} security alerts**"
)

st.divider()


# ============================================================
# NETWORK OVERVIEW
# ============================================================

st.markdown("### Network Overview")

col1, col2, col3, col4, col5 = st.columns(5)


with col1:

    st.metric(
        "Total Packets",
        f"{total_capture_packets:,}",
        help=(
            "Total number of packets physically "
            "present in the uploaded PCAP/PCAPNG."
        ),
    )


with col2:

    st.metric(
        "Analyzable Packets",
        f"{ip_analyzable_packets:,}",
        help=(
            "Packets containing the IP information "
            "used by the current traffic analysis."
        ),
    )


with col3:

    st.metric(
        "TCP Traffic",
        f"{tcp_percentage:.1f}%",
    )


with col4:

    st.metric(
        "UDP Traffic",
        f"{udp_percentage:.1f}%",
    )


with col5:

    st.metric(
        "Security Alerts",
        f"{len(alerts):,}",
    )


# ============================================================
# TABS
# ============================================================

overview_tab, traffic_tab, security_tab, packets_tab = st.tabs(
    [
        "Overview",
        "Traffic",
        "Security",
        "Packets",
    ]
)


# ============================================================
# OVERVIEW TAB
# ============================================================

with overview_tab:

    st.markdown("### Protocol Distribution")

    protocol_chart_data = protocols.reset_index()

    protocol_chart_data.columns = [
        "protocol",
        "packets",
        "percentage",
    ]

    fig_protocol = px.pie(
        protocol_chart_data,
        names="protocol",
        values="packets",
        hole=0.62,
    )

    fig_protocol.update_traces(
        textposition="inside",
        textinfo="percent+label",
    )

    fig_protocol.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(
            l=10,
            r=10,
            t=20,
            b=10,
        ),
        legend=dict(
            orientation="h",
            y=-0.05,
        ),
    )

    st.plotly_chart(
        fig_protocol,
        width="stretch",
    )


    # --------------------------------------------------------
    # PACKET STATISTICS
    # --------------------------------------------------------

    st.markdown("### Analyzed Packet Statistics")

    col1, col2, col3 = st.columns(3)


    with col1:

        st.metric(
            "Average Packet Size",
            f"{stats['average_packet_size']} bytes",
        )


    with col2:

        st.metric(
            "Largest Packet",
            f"{stats['maximum_packet_size']} bytes",
        )


    with col3:

        st.metric(
            "Smallest Packet",
            f"{stats['minimum_packet_size']} bytes",
        )


# ============================================================
# TRAFFIC TAB
# ============================================================

with traffic_tab:

    st.markdown("### Network Traffic")

    st.caption(
        "Identify the most active sources, destinations "
        "and services in the analyzed traffic."
    )


    # --------------------------------------------------------
    # TOP SOURCE / DESTINATION IPs
    # --------------------------------------------------------

    source_data = top_source_ips(df)

    destination_data = top_destination_ips(df)

    col1, col2 = st.columns(2)


    with col1:

        st.markdown("#### Top Source IPs")

        fig_source = px.bar(
            source_data,
            x="ip",
            y="packets",
        )

        fig_source.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(
                l=10,
                r=10,
                t=10,
                b=10,
            ),
            xaxis_title=None,
            yaxis_title="Packets",
        )

        st.plotly_chart(
            fig_source,
            width="stretch",
        )


    with col2:

        st.markdown("#### Top Destination IPs")

        fig_destination = px.bar(
            destination_data,
            x="ip",
            y="packets",
        )

        fig_destination.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(
                l=10,
                r=10,
                t=10,
                b=10,
            ),
            xaxis_title=None,
            yaxis_title="Packets",
        )

        st.plotly_chart(
            fig_destination,
            width="stretch",
        )


    # --------------------------------------------------------
    # MOST FREQUENTLY CONTACTED PORTS
    # --------------------------------------------------------

    st.markdown(
        "### Most Frequently Contacted Ports"
    )

    # Build port statistics directly from the dataframe.
    # This avoids the previous port-chart rendering problem.

    port_data = (
        df[
            ["destination_port"]
        ]
        .dropna()
        .copy()
    )


    port_data["destination_port"] = pd.to_numeric(
        port_data["destination_port"],
        errors="coerce",
    )


    port_data = port_data.dropna(
        subset=["destination_port"]
    )


    port_data = (
        port_data
        .groupby("destination_port")
        .size()
        .reset_index(
            name="packets"
        )
        .sort_values(
            "packets",
            ascending=False,
        )
        .head(10)
    )


    # Convert ports to strings so Plotly treats
    # them as categories instead of a continuous axis.

    port_data["destination_port"] = (
        port_data["destination_port"]
        .astype(int)
        .astype(str)
    )


    if not port_data.empty:

        fig_ports = px.bar(
            port_data,
            x="destination_port",
            y="packets",
            text="packets",
        )

        fig_ports.update_traces(
            textposition="outside"
        )

        fig_ports.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(
                l=10,
                r=10,
                t=30,
                b=10,
            ),
            xaxis_title="Destination Port",
            yaxis_title="Packets",
            xaxis=dict(
                type="category"
            ),
        )

        st.plotly_chart(
            fig_ports,
            width="stretch",
        )

    else:

        st.info(
            "No destination port information "
            "was found in the analyzed traffic."
        )


# ============================================================
# SECURITY TAB
# ============================================================

with security_tab:

    st.markdown("### Security Intelligence")

    st.caption(
        "Detected anomalies and potential security "
        "events identified from the capture."
    )


    col1, col2, col3 = st.columns(3)


    with col1:

        st.metric(
            "High Risk",
            high_alerts,
        )


    with col2:

        st.metric(
            "Medium Risk",
            medium_alerts,
        )


    with col3:

        st.metric(
            "Low Risk",
            low_alerts,
        )


    st.divider()


    if alerts.empty:

        st.success(
            "No suspicious activity detected."
        )

    else:

        for _, alert in alerts.iterrows():

            severity = str(
                alert["severity"]
            ).upper()

            if severity == "HIGH":

                st.error(
                    f"🔴 {severity} · "
                    f"{alert['type']}\n\n"
                    f"{alert['description']}"
                )

            elif severity == "MEDIUM":

                st.warning(
                    f"🟠 {severity} · "
                    f"{alert['type']}\n\n"
                    f"{alert['description']}"
                )

            else:

                st.info(
                    f"🔵 {severity} · "
                    f"{alert['type']}\n\n"
                    f"{alert['description']}"
                )


        st.markdown("### Alert Details")

        st.dataframe(
            alerts,
            width="stretch",
            hide_index=True,
        )


# ============================================================
# PACKET EXPLORER TAB
# ============================================================

with packets_tab:

    st.markdown("### Packet Explorer")

    st.caption(
        "Inspect the parsed packet-level information."
    )


    # --------------------------------------------------------
    # FILTERS
    # --------------------------------------------------------

    col1, col2 = st.columns(2)


    with col1:

        protocol_options = sorted(
            df["protocol"]
            .dropna()
            .unique()
            .tolist()
        )

        selected_protocols = st.multiselect(
            "Protocol",
            protocol_options,
            default=protocol_options,
        )


    with col2:

        source_options = sorted(
            df["source_ip"]
            .dropna()
            .unique()
            .tolist()
        )

        selected_sources = st.multiselect(
            "Source IP",
            source_options,
            default=source_options,
        )


    # --------------------------------------------------------
    # FILTER
    # --------------------------------------------------------

    filtered_df = df[
        df["protocol"].isin(
            selected_protocols
        )
        &
        df["source_ip"].isin(
            selected_sources
        )
    ]


    st.caption(
        f"Showing {len(filtered_df):,} "
        f"of {len(df):,} analyzed packets"
    )


    # --------------------------------------------------------
    # DATA TABLE
    # --------------------------------------------------------

    st.dataframe(
        filtered_df.head(1000),
        width="stretch",
        hide_index=True,
    )


    # --------------------------------------------------------
    # CSV EXPORT
    # --------------------------------------------------------

    csv_data = (
        filtered_df
        .to_csv(index=False)
        .encode("utf-8")
    )


    st.download_button(
        label="Export filtered packet data",
        data=csv_data,
        file_name="netsentinel_packet_analysis.csv",
        mime="text/csv",
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "NETSENTINEL · NETWORK SECURITY INTELLIGENCE · HACKATHON PS9"
)