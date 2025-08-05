# QuickShark — Smart & Lightweight PCAP Threat Analyzer
A fast Flask-powered tool that analyzes PCAP files to uncover protocol-based security threats such as leaked credentials, DNS abuse, port scans, SYN floods, and FTP data exposure — all through easy-to-use analysis modules.

## 🔍 Features
- HTTP Analysis: Inspects HTTP requests to detect plaintext credentials.
- DNS Intelligence: Performs DNS analysis with geolocation and integrates with VirusTotal to check IP / Domain reputation.
- TCP Detection Engine: Detects SYN flood attacks and Nmap scans using timing patterns.
- FTP Module: Extracts FTP status codes and captures username/password data.

## 🚀 Installation Steps
```bash
# Step 1: Clone the repository
git clone https://github.com/dhruvin1234/QuickShark.git

# Step 2: Go into the project folder
cd QuickShark

# Step 3: Install requirements
pip install -r requirements.txt

# Step 4: Run the application
python app.py
```
