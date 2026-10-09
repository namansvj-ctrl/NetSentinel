# NetSentinel 🛡️
### Network Traffic Analyzer & Anomaly Detection Platform

NetSentinel is a Python-based network security tool that analyzes PCAP/PCAPNG files, identifies suspicious traffic patterns, and presents network insights through an interactive dashboard.

## 🚀 Features

- **PCAP Analysis:** Upload and analyze captured network traffic.
- **Packet Inspection:** Extract IP addresses, ports, protocols, timestamps, and packet sizes.
- **Traffic Visualization:** View protocol distribution, IP statistics, and destination port activity.
- **Anomaly Detection:** Identify potential port scans, unusually high request rates, and monitored-port activity.
- **Security Alerts:** Display detected events with severity levels.
- **Packet Explorer:** Filter and investigate individual packet records.
- **CSV Export:** Export analyzed packet data for further investigation.

## 🛠️ Technologies Used

- **Language:** Python
- **Packet Analysis:** Scapy
- **Data Processing:** Pandas
- **Visualization:** Plotly
- **Dashboard:** Streamlit
- **Version Control:** Git and GitHub

## 📁 Project Structure

```text
NetSentinel/
├── app.py
├── analyzer.py
├── anomaly_detector.py
├── generate_test_pcap.py
├── requirements.txt
├── README.md
├── data/
│   └── sample.pcap
└── screenshots/
```

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/namansvj-ctrl/NetSentinel.git
cd NetSentinel
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the environment

**Windows PowerShell:**

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the application

```bash
python -m streamlit run app.py
```

### 6. Open the dashboard

Open the local URL displayed in the terminal, usually:

`http://localhost:8501`

Upload a PCAP or PCAPNG file to begin analyzing network traffic.

## 🧪 Generate Test Data

To generate the project's controlled demonstration capture, run:

```bash
python generate_test_pcap.py
```

The generated capture is saved as `data/sample.pcap`. Upload it to the dashboard to test the analysis and detection features.

## 🔍 Detection Methods

NetSentinel currently uses rule-based detection to flag:

- **Port Scanning:** A source contacting many unique destination ports.
- **High Request Rates:** A source generating a high number of packets within a short time window.
- **Monitored-Port Activity:** Traffic involving commonly monitored ports such as FTP (21), Telnet (23), SMB (445), RDP (3389), and VNC (5900).

These alerts indicate potentially suspicious behavior and require further investigation; they do not independently prove that an attack occurred.

## 🏗️ How It Works

1. Upload a PCAP/PCAPNG capture.
2. Extract packet details using Scapy.
3. Organize and analyze the extracted data using Pandas.
4. Apply rule-based detection to identify suspicious patterns.
5. Display traffic statistics and security alerts through Streamlit.
6. Investigate packets and export the results as CSV.

## 🎯 Project Objective

To simplify network traffic investigation by combining packet analysis, explainable anomaly detection, and interactive visualization in one platform.

## 🔮 Future Enhancements

- Machine-learning-based anomaly detection.
- Real-time network traffic monitoring.
- Threat intelligence integration.
- Advanced behavioral analysis and reporting.

*These are proposed enhancements and are not part of the current implementation.*

## ⚠️ Limitations

- Detection depends on predefined rules and thresholds.
- Alerts may include false positives and require human investigation.
- Processing capacity depends on capture size and available system resources.
- The current application analyzes uploaded capture files rather than providing continuous live monitoring.

## 👥 Team

**Project:** NetSentinel  
**Category:** Cybersecurity / Network Traffic Analysis  
**Problem Statement:** PS9

## 📜 License

This project is intended for educational, research, and hackathon demonstration purposes.
