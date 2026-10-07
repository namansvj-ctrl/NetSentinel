import os
import tempfile

import pandas as pd
import plotly.express as px
import streamlit as st

from analyzer import load_packets, analyze_packets
from anomaly_detector import detect_anomalies


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="NetSentinel | Network Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# FUTURISTIC THEME
# ============================================================

st.markdown(
    """
    <style>

    /* ======================================================
       GLOBAL
       ====================================================== */

    .stApp {
        background:
            radial-gradient(
                circle at 80% 0%,
                rgba(0, 200, 255, 0.055),
                transparent 28%
            ),
            radial-gradient(
                circle at 10% 20%,
                rgba(90, 70, 255, 0.035),
                transparent 25%
            ),
            #07090d;
    }

    .main .block-container {
        max-width: 1480px;
        padding-top: 2rem;
        padding-bottom: 4rem;
        padding-left: 3rem;
        padding-right: 3rem;
    }


    /* ======================================================
       TYPOGRAPHY
       ====================================================== */

    html,
    body,
    [class*="css"] {
        font-family:
            Inter,
            -apple-system,
            BlinkMacSystemFont,
            "Segoe UI",
            sans-serif;
    }

    h1 {
        font-size: 2.65rem !important;
        font-weight: 700 !important;
        letter-spacing: -1.5px !important;
    }

    h2 {
        font-size: 1.45rem !important;
        font-weight: 650 !important;
        letter-spacing: -0.5px !important;
    }

    h3 {
        font-size: 1.05rem !important;
        font-weight: 600 !important;
    }

    p,
    label,
    .stCaption {
        color: #9299a6;
    }


    /* ======================================================
       SIDEBAR
       ====================================================== */

    section[data-testid="stSidebar"] {
        background:
            linear-gradient(
                180deg,
                #090c11 0%,
                #07090d 100%
            );

        border-right: 1px solid rgba(255,255,255,0.06);
    }

    section[data-testid="stSidebar"] > div {
        padding-top: 1.5rem;
    }


    /* ======================================================
       METRIC CARDS
       ====================================================== */

    div[data-testid="stMetric"] {
        background:
            linear-gradient(
                145deg,
                rgba(255,255,255,0.045),
                rgba(255,255,255,0.018)
            );

        border: 1px solid rgba(255,255,255,0.075);

        border-radius: 14px;

        padding: 1.15rem 1.25rem;

        box-shadow:
            0 8px 30px rgba(0,0,0,0.18);

        transition:
            transform 0.2s ease,
            border-color 0.2s ease;
    }

    div[data-testid="stMetric"]:hover {
        transform: translateY(-2px);

        border-color:
            rgba(0, 210, 255, 0.25);

        box-shadow:
            0 10px 35px rgba(0,180,255,0.08);
    }

    div[data-testid="stMetricLabel"] {
        color: #7f8997 !important;
        font-size: 0.76rem !important;
        text-transform: uppercase;
        letter-spacing: 1.1px;
        font-weight: 600;
    }

    div[data-testid="stMetricValue"] {
        color: #f2f6fb !important;
        font-size: 1.8rem !important;
        font-weight: 700 !important;
    }


    /* ======================================================
       CONTAINERS
       ====================================================== */

    div[data-testid="stVerticalBlockBorderWrapper"] {
        background:
            linear-gradient(
                145deg,
                rgba(255,255,255,0.035),
                rgba(255,255,255,0.012)
            );

        border:
            1px solid rgba(255,255,255,0.065);

        border-radius: 16px;
    }


    /* ======================================================
       BUTTONS
       ====================================================== */

    .stButton > button {
        width: 100%;

        border-radius: 9px;

        border: 1px solid
            rgba(0, 210, 255, 0.25);

        background:
            linear-gradient(
                135deg,
                rgba(0, 180, 255, 0.13),
                rgba(80, 70, 255, 0.09)
            );

        color: #dff8ff;

        font-weight: 600;

        transition: all 0.2s ease;
    }

    .stButton > button:hover {
        border-color:
            rgba(0, 220, 255, 0.65);

        background:
            rgba(0, 200, 255, 0.14);

        transform: translateY(-1px);
    }


    /* ======================================================
       FILE UPLOADER
       ====================================================== */

    section[data-testid="stFileUploaderDropzone"] {
        background:
            rgba(255,255,255,0.018);

        border:
            1px dashed
            rgba(0, 210, 255, 0.24);

        border-radius: 12px;
    }

    section[data-testid="stFileUploaderDropzone"]:hover {
        border-color:
            rgba(0, 210, 255, 0.55);
    }


    /* ======================================================
       TABS
       ====================================================== */

    button[data-baseweb="tab"] {
        font-weight: 600;
        color: #707987;
        padding-left: 1rem;
        padding-right: 1rem;
    }

    button[data-baseweb="tab"][aria-selected="true"] {
        color: #62dcff !important;
    }

    div[data-baseweb="tab-highlight"] {
        background-color: #28c7f5 !important;
    }


    /* ======================================================
       DATAFRAME
       ====================================================== */

    div[data-testid="stDataFrame"] {
        border:
            1px solid rgba(255,255,255,0.065);

        border-radius: 12px;
        overflow: hidden;
    }


    /* ======================================================
       DIVIDERS
       ====================================================== */

    hr {
        border-color:
            rgba(255,255,255,0.06) !important;
    }


    /* ======================================================
       ALERT COLORS
       ====================================================== */

    .high-text {
        color: #ff5d6c;
        font-weight: 700;
    }

    .medium-text {
        color: #ffb84d;
        font-weight: 700;
    }

    .low-text {
        color: #54c7ff;
        font-weight: 700;
    }


    /* ======================================================
       BRAND
       ====================================================== */

    .brand-title {
        font-size: 1.15rem;
        font-weight: 750;
        letter-spacing: 0.3px;
        color: #edfaff;
    }

    .brand-subtitle {
        font-size: 0.7rem;
        letter-spacing: 1.6px;
        text-transform: uppercase;
        color: #66717e;
    }

    .status-dot {
        color: #39e6a5;
        font-size: 0.75rem;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SIDEBAR BRAND
# ============================================================

with st.sidebar:

    st.markdown(
        """
        <div class="brand-title">🛡️ NetSentinel</div>
        <div class="brand-subtitle">Network Intelligence Platform</div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("")

    st.markdown(
        '<span class="status-dot">●</span> ANALYSIS ENGINE READY',
        unsafe_allow_html=True,
    )

    st.divider()

    st.markdown("### Capture")

    uploaded_file = st.file_uploader(
        "Upload network capture",
        type=["pcap", "pcapng"],
        help="Upload a PCAP or PCAPNG network capture.",
    )

    st.caption(
        "Supported formats: PCAP · PCAPNG"
    )

    st.divider()

    st.markdown("### Detection Engine")

    st.markdown(
        """
        **PORT SCAN**  
        Detects large-scale port enumeration.

        **REQUEST RATE**  
        Detects unusually high packet activity.

        **SUSPICIOUS PORTS**  
        Monitors commonly targeted services.
        """
    )

    st.divider()

    st.caption(
        "NetSentinel v1.0 • Hackathon Prototype"
    )


# ============================================================
# SESSION STATE
# ============================================================

if "analysis_complete" not in st.session_state:
    st.session_state.analysis_complete = False

if "df" not in st.session_state:
    st.session_state.df = None

if "alerts" not in st.session_state:
    st.session_state.alerts = None

if "total_packets" not in st.session_state:
    st.session_state.total_packets = 0

if "file_signature" not in st.session_state:
    st.session_state.file_signature = None


# ============================================================
# HERO
# ============================================================

hero_col1, hero_col2 = st.columns(
    [4.8, 1.2]
)

with hero_col1:

    st.markdown(
        """
        <div style="
            color:#6d7785;
            font-size:0.72rem;
            font-weight:600;
            letter-spacing:2px;
            text-transform:uppercase;
            margin-bottom:0.5rem;
        ">
            NETWORK SECURITY · TRAFFIC INTELLIGENCE
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.title("Network Intelligence Center")

    st.caption(
        "Transform raw packet captures into actionable network security intelligence."
    )

with hero_col2:

    st.markdown(
        """
        <div style="
            text-align:right;
            padding-top:1.2rem;
            color:#687481;
            font-size:0.75rem;
        ">
        SYSTEM STATUS<br>
        <span style="
            color:#39e6a5;
            font-weight:700;
            letter-spacing:1px;
        ">
        ● OPERATIONAL
        </span>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# PROCESS UPLOAD
# ============================================================

if uploaded_file is not None:

    file_signature = (
        uploaded_file.name,
        uploaded_file.size,
    )

    if (
        st.session_state.file_signature
        != file_signature
    ):

        st.session_state.file_signature = (
            file_signature
        )

        st.session_state.analysis_complete = False

        temp_path = None

        with st.spinner(
            "Parsing capture and building network intelligence..."
        ):

            try:

                suffix = (
                    ".pcapng"
                    if uploaded_file.name.lower().endswith(
                        ".pcapng"
                    )
                    else ".pcap"
                )

                with tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix=suffix,
                ) as temp_file:

                    temp_file.write(
                        uploaded_file.getbuffer()
                    )

                    temp_path = temp_file.name

                packets = load_packets(
                    temp_path
                )

                total_packets = len(packets)

                df = analyze_packets(
                    packets
                )

                alerts = detect_anomalies(
                    df
                )

                st.session_state.total_packets = (
                    total_packets
                )

                st.session_state.analyzed_packets = (
                    len(df)
                )

                st.session_state.df = df

                st.session_state.alerts = alerts

                st.session_state.analysis_complete = True

            except Exception as e:

                st.error(
                    f"Analysis failed: {e}"
                )

                st.session_state.analysis_complete = False

            finally:

                if (
                    temp_path
                    and os.path.exists(temp_path)
                ):

                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass


# ============================================================
# EMPTY STATE
# ============================================================

if not st.session_state.analysis_complete:

    st.divider()

    st.info(
        "Upload a PCAP or PCAPNG capture from the sidebar to initialize the security analysis."
    )

    st.markdown("### Analysis Pipeline")

    pipeline = st.columns(5)

    pipeline_data = [
        ("01", "CAPTURE", "PCAP / PCAPNG"),
        ("02", "PARSE", "Packet extraction"),
        ("03", "PROFILE", "Traffic intelligence"),
        ("04", "DETECT", "Anomaly rules"),
        ("05", "INVESTIGATE", "Security insights"),
    ]

    for column, item in zip(
        pipeline,
        pipeline_data,
    ):

        number, title, description = item

        with column:

            with st.container(
                border=True
            ):

                st.caption(number)

                st.markdown(
                    f"**{title}**"
                )

                st.caption(
                    description
                )

    st.stop()


# ============================================================
# DATA
# ============================================================

df = st.session_state.df
alerts = st.session_state.alerts

total_packets = (
    st.session_state.total_packets
)

analyzed_packets = (
    st.session_state.analyzed_packets
)


# ============================================================
# CORE METRICS
# ============================================================

tcp_packets = int(
    (df["protocol"] == "TCP").sum()
)

udp_packets = int(
    (df["protocol"] == "UDP").sum()
)

icmp_packets = int(
    (df["protocol"] == "ICMP").sum()
)

arp_packets = int(
    (df["protocol"] == "ARP").sum()
)

ipv6_packets = int(
    (df["protocol"] == "IPv6").sum()
)

dns_packets = int(
    (df["application_protocol"] == "DNS").sum()
)

ip_packets = int(
    (
        df["source_ip"].notna()
        & df["destination_ip"].notna()
    ).sum()
)

high_alerts = int(
    (
        alerts["severity"] == "HIGH"
    ).sum()
) if not alerts.empty else 0

medium_alerts = int(
    (
        alerts["severity"] == "MEDIUM"
    ).sum()
) if not alerts.empty else 0

low_alerts = int(
    (
        alerts["severity"] == "LOW"
    ).sum()
) if not alerts.empty else 0


# ============================================================
# CAPTURE INFO
# ============================================================

with st.container(border=True):

    info1, info2, info3 = st.columns(
        [2.5, 1, 1]
    )

    with info1:

        st.caption("ACTIVE CAPTURE")

        st.markdown(
            f"**{uploaded_file.name}**"
        )

    with info2:

        st.caption("PACKET COVERAGE")

        st.markdown(
            f"**{analyzed_packets:,} / {total_packets:,}**"
        )

    with info3:

        st.caption("IP VISIBILITY")

        st.markdown(
            f"**{ip_packets:,} packets**"
        )


st.markdown("")


# ============================================================
# TOP METRICS
# ============================================================

m1, m2, m3, m4, m5 = st.columns(5)

with m1:

    st.metric(
        "TOTAL PACKETS",
        f"{total_packets:,}",
    )

with m2:

    st.metric(
        "ANALYZED",
        f"{analyzed_packets:,}",
    )

with m3:

    st.metric(
        "TCP",
        f"{tcp_packets:,}",
    )

with m4:

    st.metric(
        "UDP",
        f"{udp_packets:,}",
    )

with m5:

    st.metric(
        "ALERTS",
        f"{len(alerts):,}",
    )


st.markdown("")


# ============================================================
# TABS
# ============================================================

overview_tab, traffic_tab, alerts_tab, explorer_tab = st.tabs(
    [
        "◈  OVERVIEW",
        "⌁  TRAFFIC",
        "⚠  SECURITY",
        "⌕  PACKET EXPLORER",
    ]
)


# ============================================================
# OVERVIEW
# ============================================================

with overview_tab:

    st.markdown("### Traffic Overview")

    chart1, chart2 = st.columns(2)

    with chart1:

        with st.container(
            border=True
        ):

            st.markdown(
                "**Protocol Distribution**"
            )

            protocol_data = (
                df["protocol"]
                .value_counts()
                .reset_index()
            )

            protocol_data.columns = [
                "protocol",
                "packets",
            ]

            fig = px.pie(
                protocol_data,
                names="protocol",
                values="packets",
                hole=0.58,
            )

            fig.update_layout(
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
                    y=-0.08,
                ),
            )

            fig.update_traces(
                textposition="inside",
                textinfo="percent",
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
            )


    with chart2:

        with st.container(
            border=True
        ):

            st.markdown(
                "**Packet Size Distribution**"
            )

            fig = px.histogram(
                df,
                x="packet_size",
                nbins=35,
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(
                    l=10,
                    r=10,
                    t=20,
                    b=10,
                ),
                xaxis_title="Packet Size (bytes)",
                yaxis_title="Packets",
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
            )


    st.markdown("### Traffic Composition")

    composition = pd.DataFrame(
        {
            "Protocol": [
                "TCP",
                "UDP",
                "ICMP",
                "ARP",
                "IPv6",
                "DNS",
            ],
            "Packets": [
                tcp_packets,
                udp_packets,
                icmp_packets,
                arp_packets,
                ipv6_packets,
                dns_packets,
            ],
        }
    )

    st.dataframe(
        composition,
        use_container_width=True,
        hide_index=True,
    )


# ============================================================
# TRAFFIC ANALYSIS
# ============================================================

with traffic_tab:

    st.markdown("### Traffic Analysis")

    port_data = (
        df[
            df["destination_port"].notna()
        ][
            ["destination_port"]
        ]
        .copy()
    )

    if not port_data.empty:

        port_data[
            "destination_port"
        ] = pd.to_numeric(
            port_data[
                "destination_port"
            ],
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

        port_data[
            "destination_port"
        ] = (
            port_data[
                "destination_port"
            ]
            .astype(int)
            .astype(str)
        )

        with st.container(
            border=True
        ):

            st.markdown(
                "**Most Frequently Contacted Ports**"
            )

            fig = px.bar(
                port_data,
                x="destination_port",
                y="packets",
                text="packets",
            )

            fig.update_traces(
                textposition="outside"
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(
                    type="category"
                ),
                margin=dict(
                    l=20,
                    r=20,
                    t=25,
                    b=20,
                ),
            )

            st.plotly_chart(
                fig,
                use_container_width=True,
            )

    else:

        st.info(
            "No TCP/UDP destination ports detected."
        )


    st.markdown("### Network Endpoints")

    c1, c2 = st.columns(2)

    with c1:

        with st.container(
            border=True
        ):

            st.markdown(
                "**Top Source IPs**"
            )

            source_data = (
                df["source_ip"]
                .dropna()
                .value_counts()
                .head(10)
                .reset_index()
            )

            source_data.columns = [
                "source_ip",
                "packets",
            ]

            st.dataframe(
                source_data,
                use_container_width=True,
                hide_index=True,
            )

    with c2:

        with st.container(
            border=True
        ):

            st.markdown(
                "**Top Destination IPs**"
            )

            destination_data = (
                df["destination_ip"]
                .dropna()
                .value_counts()
                .head(10)
                .reset_index()
            )

            destination_data.columns = [
                "destination_ip",
                "packets",
            ]

            st.dataframe(
                destination_data,
                use_container_width=True,
                hide_index=True,
            )


# ============================================================
# SECURITY
# ============================================================

with alerts_tab:

    st.markdown("### Security Command Center")

    st.caption(
        "Rule-based detection results generated from the active capture."
    )

    a1, a2, a3 = st.columns(3)

    with a1:

        st.metric(
            "HIGH",
            high_alerts,
        )

    with a2:

        st.metric(
            "MEDIUM",
            medium_alerts,
        )

    with a3:

        st.metric(
            "LOW",
            low_alerts,
        )


    st.markdown("")


    if alerts.empty:

        with st.container(
            border=True
        ):

            st.success(
                "No suspicious activity detected by the current detection rules."
            )

    else:

        for _, alert in alerts.iterrows():

            severity = alert[
                "severity"
            ]

            if severity == "HIGH":

                icon = "🔴"

            elif severity == "MEDIUM":

                icon = "🟠"

            else:

                icon = "🔵"

            with st.container(
                border=True
            ):

                left, right = st.columns(
                    [4, 1]
                )

                with left:

                    st.markdown(
                        f"### {icon} {severity} · {alert['alert_type']}"
                    )

                    st.write(
                        alert["details"]
                    )

                with right:

                    st.caption(
                        "SOURCE"
                    )

                    st.code(
                        str(
                            alert[
                                "source_ip"
                            ]
                        )
                    )

                    st.caption(
                        "DESTINATION"
                    )

                    st.code(
                        str(
                            alert[
                                "destination_ip"
                            ]
                        )
                    )


        st.download_button(
            "↓  Export Security Alerts",
            data=alerts.to_csv(
                index=False
            ).encode("utf-8"),
            file_name=(
                "netsentinel_security_alerts.csv"
            ),
            mime="text/csv",
        )


# ============================================================
# PACKET EXPLORER
# ============================================================

with explorer_tab:

    st.markdown(
        "### Packet-Level Investigation"
    )

    st.caption(
        "Filter and inspect individual packets from the analyzed capture."
    )

    f1, f2, f3 = st.columns(3)

    with f1:

        protocols = sorted(
            df["protocol"]
            .dropna()
            .unique()
            .tolist()
        )

        selected_protocols = st.multiselect(
            "Protocol",
            protocols,
            default=protocols,
        )

    with f2:

        source_options = sorted(
            df["source_ip"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

        selected_sources = st.multiselect(
            "Source IP",
            source_options,
        )

    with f3:

        destination_options = sorted(
            df["destination_ip"]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

        selected_destinations = st.multiselect(
            "Destination IP",
            destination_options,
        )


    filtered_df = df.copy()


    if selected_protocols:

        filtered_df = filtered_df[
            filtered_df[
                "protocol"
            ].isin(
                selected_protocols
            )
        ]


    if selected_sources:

        filtered_df = filtered_df[
            filtered_df[
                "source_ip"
            ]
            .astype(str)
            .isin(
                selected_sources
            )
        ]


    if selected_destinations:

        filtered_df = filtered_df[
            filtered_df[
                "destination_ip"
            ]
            .astype(str)
            .isin(
                selected_destinations
            )
        ]


    with st.container(
        border=True
    ):

        st.markdown(
            f"**{len(filtered_df):,}** packets displayed "
            f"out of **{len(df):,}** analyzed"
        )

        display_columns = [
            "packet_number",
            "timestamp",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "protocol",
            "application_protocol",
            "packet_size",
        ]

        st.dataframe(
            filtered_df[
                display_columns
            ],
            use_container_width=True,
            height=520,
            hide_index=True,
        )


    csv_data = filtered_df.to_csv(
        index=False
    ).encode("utf-8")


    st.download_button(
        "↓  Export Filtered Packet Data",
        data=csv_data,
        file_name=(
            "netsentinel_packets.csv"
        ),
        mime="text/csv",
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

footer1, footer2 = st.columns(
    [4, 1]
)

with footer1:

    st.caption(
        "NETSENTINEL  •  Network Traffic Intelligence"
    )

with footer2:

    st.caption(
        "PCAP / PCAPNG  •  v1.0"
    )