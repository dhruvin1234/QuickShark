import os
import pandas as pd
import pyshark
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.utils import secure_filename
from pyvis.network import Network
import networkx as nx 
import scapy.all as scapy 
from flask import Flask, render_template, request
import subprocess
import json
from collections import Counter
from modules.dns_analysis import extract_dns_info
from flask import Flask, render_template, jsonify, session
import pyshark
from collections import Counter



app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Allowed file extensions for upload
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.before_request
def reset_session_data():
    if 'filtered_data' not in session:
        session['filtered_data'] = []

@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join('uploads', filename)
        file.save(file_path)

        session['uploaded_file'] = file_path

        # Process the PCAP file and store data
        df, total_packets, unique_ips, protocol_counts, top_ips = process_pcap(file_path)
        session['filtered_data'] = df.to_dict(orient='records')
        session['stats'] = {
            "total_packets": total_packets,
            "unique_ips": unique_ips,
            "protocol_counts": protocol_counts,
            "top_ips": top_ips
        }

        return redirect(url_for('filter_data'))

    return 'Invalid file format. Please upload a valid PCAP file.'

import pyshark
import pandas as pd

def process_pcap(file_path):
    data = []

    # Open PCAP file with optimized settings
    cap = pyshark.FileCapture(
        file_path, 
        keep_packets=False, 
        use_json=True,  
        include_raw=False  
    )

    for packet in cap:
        try:
            src_ip, dst_ip, src_port, dst_port = "N/A", "N/A", "N/A", "N/A"
            protocol = packet.highest_layer
            details = {}

            # 🌐 Network Layer (IPv4, IPv6, ARP, ICMP)
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                src_ip = packet.ipv6.src
                dst_ip = packet.ipv6.dst
            elif hasattr(packet, 'arp'):
                src_ip = getattr(packet.arp, 'src_proto_ipv4', "N/A")
                dst_ip = getattr(packet.arp, 'dst_proto_ipv4', "N/A")
                protocol = "ARP"
            elif hasattr(packet, 'icmp'):
                protocol = "ICMP"
            elif hasattr(packet, 'ICMP'):
                protocol = "icmp"

            # 🔄 Transport Layer (TCP, UDP)
            if hasattr(packet, 'tcp'):
                src_port = getattr(packet.tcp, 'srcport', "N/A")
                dst_port = getattr(packet.tcp, 'dstport', "N/A")
                protocol = "TCP"
            elif hasattr(packet, 'udp'):
                src_port = getattr(packet.udp, 'srcport', "N/A")
                dst_port = getattr(packet.udp, 'dstport', "N/A")
                protocol = "UDP"

            # 🌍 Application Layer (HTTP, DNS, FTP, SMB, TLS)
            if hasattr(packet, 'http'):
                protocol = "HTTP"
                details = {
                    "Host": getattr(packet.http, 'host', "N/A"),
                    "User-Agent": getattr(packet.http, 'user_agent', "N/A"),
                    "Referer": getattr(packet.http, 'referer', "N/A"),
                    "Authorization": getattr(packet.http, 'authorization', "N/A"),
                    "Cookies": getattr(packet.http, 'cookie', "N/A"),
                    "Request Method": getattr(packet.http, 'request_method', "N/A"),
                    "Response Code": getattr(packet.http, 'response_code', "N/A"),
                    "Content Type": getattr(packet.http, 'content_type', "N/A"),
                }

            elif hasattr(packet, 'dns'):
                protocol = "DNS"
                details = {
                    "Query Name": getattr(packet.dns, 'qry_name', "N/A"),
                    "Response IP": getattr(packet.dns, 'a', "N/A"),
                    "Query Type": getattr(packet.dns, 'qry_type', "N/A"),
                    "Response Name": getattr(packet.dns, 'resp_name', "N/A"),
                }

            elif hasattr(packet, 'ftp'):
                protocol = "FTP"
                details = {}
                if hasattr(packet.ftp, 'request_command'):
                    command = packet.ftp.request_command
                    if command == "USER":
                        details["Username"] = getattr(packet.ftp, 'request_arg', "N/A")
                    elif command == "PASS":
                        details["Password"] = getattr(packet.ftp, 'request_arg', "N/A")

            elif hasattr(packet, 'smb'):
                protocol = "SMB"
                details = {
                    "Username": getattr(packet.smb, 'username', "N/A"),
                    "Session ID": getattr(packet.smb, 'session_id', "N/A"),
                    "Tree ID": getattr(packet.smb, 'tree_id', "N/A"),
                }

            elif hasattr(packet, 'tls') and hasattr(packet.tls, 'handshake_extensions_server_name'):
                protocol = "TLS"
                details = {
                    "SNI": getattr(packet.tls, 'handshake_extensions_server_name', "N/A"),
                    "Cipher Suite": getattr(packet.tls, 'handshake_ciphersuite', "N/A"),
                }

            # Remove empty fields
            details = {k: v for k, v in details.items() if v != "N/A"}

            # ✅ Store parsed data
            data.append((src_ip, dst_ip, protocol, src_port, dst_port, details if details else "{}"))

        except Exception as e:
            print(f"Error processing packet: {e}")  # Debugging output

    cap.close()  # Free memory

    # Convert data to Pandas DataFrame
    df = pd.DataFrame(data, columns=['Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port', 'Details'])

    # 📊 Summary statistics
    total_packets = len(df)
    unique_ips = len(set(df['Source IP']) | set(df['Destination IP']))
    protocol_counts = df["Protocol"].value_counts().to_dict()
    top_ips = df['Source IP'].value_counts().head(5).to_dict()

    return df, total_packets, unique_ips, protocol_counts, top_ips



@app.route('/stats')
def stats():
    stats_data = session.get('stats', {})
    return render_template('stats.html', 
                           total_packets=stats_data.get("total_packets", 0), 
                           unique_ips=stats_data.get("unique_ips", 0), 
                           protocol_counts=stats_data.get("protocol_counts", {}), 
                           top_ips=stats_data.get("top_ips", {}))

@app.route('/filter', methods=['GET', 'POST'])
def filter_data():
    original_data = session.get('filtered_data', [])  # Retrieve original dataset
    df = pd.DataFrame(original_data)  # Convert to DataFrame (Avoid modifying session directly)

    stats_data = session.get('stats', {})

    if request.method == 'POST':
        # 🌍 Network & Transport Layer Filters
        src_ip = request.form.get('src_ip', '')
        dst_ip = request.form.get('dst_ip', '')
        protocol = request.form.get('protocol', '')
        src_port = request.form.get('src_port', '')
        dst_port = request.form.get('dst_port', '')

        # 🌐 Application-Layer Filters
        http_host = request.form.get('http_host', '')
        user_agent = request.form.get('user_agent', '')
        dns_query = request.form.get('dns_query', '')
        ftp_user = request.form.get('ftp_user', '')

        # 🌍 Apply Network & Transport Layer Filters
        if src_ip:
            df = df[df['Source IP'].str.contains(src_ip, case=False, na=False)]
        if dst_ip:
            df = df[df['Destination IP'].str.contains(dst_ip, case=False, na=False)]
        if protocol:
            df = df[df['Protocol'].str.contains(protocol, case=False, na=False)]
        if src_port:
            df = df[df['Source Port'].astype(str).str.contains(src_port, na=False)]
        if dst_port:
            df = df[df['Destination Port'].astype(str).str.contains(dst_port, na=False)]

        # 🌐 Apply Application-Layer Filters (Only if these columns exist)
        if 'HTTP Host' in df.columns and http_host:
            df = df[df['HTTP Host'].str.contains(http_host, case=False, na=False)]
        if 'User-Agent' in df.columns and user_agent:
            df = df[df['User-Agent'].str.contains(user_agent, case=False, na=False)]
        if 'DNS Query' in df.columns and dns_query:
            df = df[df['DNS Query'].str.contains(dns_query, case=False, na=False)]
        if 'FTP Username' in df.columns and ftp_user:
            df = df[df['FTP Username'].str.contains(ftp_user, case=False, na=False)]

        filtered_data = df.to_dict(orient='records')
    else:
        filtered_data = original_data  # Keep unfiltered data if no input

    df.drop_duplicates(subset=['Source IP', 'Destination IP', 'Protocol', 'Source Port', 'Destination Port'], keep='first', inplace=True)

    return render_template('filter.html', 
                           data=filtered_data,  # Send filtered data
                           protocol_counts=stats_data.get("protocol_counts", {}), 
                           top_ips=stats_data.get("top_ips", {}))



    
# Function to extract network connections from PCAP
def extract_connections(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    connections = set()
    
    for packet in packets:
        if packet.haslayer(scapy.IP):
            src = packet[scapy.IP].src
            dst = packet[scapy.IP].dst
            connections.add((src, dst))

    return connections
    
    
import os

UPLOAD_FOLDER = "uploads"  # Ensure this is the correct folder where PCAPs are stored

def get_latest_uploaded_pcap():
    """Retrieve the most recently uploaded PCAP file."""
    pcap_files = [f for f in os.listdir(UPLOAD_FOLDER) if f.endswith(".pcap")]
    if not pcap_files:
        return None  # No PCAP files found

    latest_pcap = max(pcap_files, key=lambda f: os.path.getctime(os.path.join(UPLOAD_FOLDER, f)))
    return os.path.join(UPLOAD_FOLDER, latest_pcap)  # Return full path of latest PCAP


from flask import Flask, render_template, request, session, jsonify
import scapy.all as scapy



import scapy.all as scapy

def extract_full_packet_details(pcap_file):
    """Extract highly accurate packet details, similar to Wireshark."""
    packets = scapy.rdpcap(pcap_file)
    packet_details = []

    for index, packet in enumerate(packets):
        packet_info = {
            "Packet Number": index + 1,
            "Raw Data": packet.show(dump=True),  # Extract full packet details
            "Headers": {}  # Store headers separately
        }

        # Ethernet Layer
        if packet.haslayer(scapy.Ether):
            packet_info["Headers"]["Ethernet"] = {
                "Source MAC": packet[scapy.Ether].src,
                "Destination MAC": packet[scapy.Ether].dst,
               
            }

        # IP Layer
        if packet.haslayer(scapy.IP):
            packet_info["Headers"]["IP"] = {
                "Source IP": packet[scapy.IP].src,
                "Destination IP": packet[scapy.IP].dst,
                "TTL": packet[scapy.IP].ttl,
                
            }

        # TCP Layer (No Protocol Mapping, Only Numbers)
        if packet.haslayer(scapy.TCP):
            packet_info["Headers"]["TCP"] = {
                "Source Port": packet[scapy.TCP].sport,
                "Destination Port": packet[scapy.TCP].dport,
                "Sequence Number": packet[scapy.TCP].seq,
                "Acknowledgment Number": packet[scapy.TCP].ack,
                "Flags": str(packet[scapy.TCP].flags)  # Keep raw flag values
            }

        # UDP Layer
        if packet.haslayer(scapy.UDP):
            packet_info["Headers"]["UDP"] = {
                "Source Port": packet[scapy.UDP].sport,
                "Destination Port": packet[scapy.UDP].dport,
                "Length": packet[scapy.UDP].len
            }

        # ICMP Layer
        if packet.haslayer(scapy.ICMP):
            packet_info["Headers"]["ICMP"] = {
                "Type": packet[scapy.ICMP].type,
                #"Code": packet[scapy.ICMP].code,
               # "Checksum": packet[scapy.ICMP].chksum
            }

        # Application Layer (HTTP, DNS, etc.)
       # if packet.haslayer(scapy.Raw):
        #    packet_info["Headers"]["Raw Payload"] = packet[scapy.Raw].load.hex()  # Hex-encoded raw data

        packet_details.append(packet_info)

    return packet_details

from flask import render_template, session

@app.route('/packet-details/<int:packet_id>')
def packet_details(packet_id):
    """Display full details of a selected packet."""
    pcap_file = session.get('uploaded_file', None)
    if not pcap_file:
        return "No PCAP file uploaded.", 400

    packet_details = extract_full_packet_details(pcap_file)
    
    if packet_id > len(packet_details) or packet_id < 1:
        return "Packet not found.", 404

    selected_packet = packet_details[packet_id - 1]
    return render_template("packet_details.html", packet=selected_packet)



# Generate Network Graph
def generate_network_graph(pcap_file):
    net = Network(height="700px", width="100%", bgcolor="#222222", font_color="white")
    
    G = nx.Graph()
    connections = extract_connections(pcap_file)

    for src, dst in connections:
        G.add_node(src, title=src)
        G.add_node(dst, title=dst)
        G.add_edge(src, dst)

    net.from_nx(G)
    net.save_graph("templates/network_graph.html")

@app.route('/network-graph')
def network_graph():
    latest_pcap = get_latest_uploaded_pcap()
    if latest_pcap:
        generate_network_graph(latest_pcap)  # Generate network graph for the latest PCAP
    return render_template("network_graph.html")

from flask import Flask, render_template, session
import scapy.all as scapy

import requests
import scapy.all as scapy
from flask import render_template, session


'''
# API Keys (Replace with actual keys)
ABUSEIPDB_API_KEY = "f53217d28d225b4d629d9fd8bfa7f844bc2598f3531dbe6d260edbad2cca3c14d9d00f5efb75c304"
VIRUSTOTAL_API_KEY = "cb8762127f18035d3f2cd7868201f1fb563964ee77ba760d6ca88f0fabd49f63"

def check_ip_threat(ip):
    """Check if the given IP is malicious using AbuseIPDB and VirusTotal."""
    threat_data = {"AbuseIPDB": "Unknown", "VirusTotal": "Unknown"}

    try:
        # Check AbuseIPDB
        abuseipdb_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        response = requests.get(abuseipdb_url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data["data"]["abuseConfidenceScore"] > 50:  # Customize threshold
                threat_data["AbuseIPDB"] = "Malicious"
            else:
                threat_data["AbuseIPDB"] = "Safe"

        # Check VirusTotal
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(vt_url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
                threat_data["VirusTotal"] = "Malicious"
            else:
                threat_data["VirusTotal"] = "Safe"

    except Exception as e:
        print(f"Error checking threat intelligence: {e}")

    return threat_data
    
    '''


@app.route('/ip-packets/<ip_address>')
def ip_packets(ip_address):
    """Fetch all packets related to the selected IP from the PCAP file."""
    pcap_file = session.get('uploaded_file', None)
    if not pcap_file:
        return "No PCAP file uploaded.", 400

    packets = scapy.rdpcap(pcap_file)
    ip_packets_list = []

    for packet in packets:
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            if src_ip == ip_address or dst_ip == ip_address:
                packet_info = {
                    "Source IP": src_ip,
                    "Destination IP": dst_ip,
                    "Raw Data": packet.show(dump=True),
                    "Headers": {}
                }

                # Ethernet Layer
                if packet.haslayer(scapy.Ether):
                    packet_info["Headers"]["Ethernet"] = {
                        "Source MAC": packet[scapy.Ether].src,
                        "Destination MAC": packet[scapy.Ether].dst,
                       
                    }

                # IP Layer
                packet_info["Headers"]["IP"] = {
                    "Source IP": src_ip,
                    "Destination IP": dst_ip,
                    "TTL": packet[scapy.IP].ttl,
                    
                }

                # TCP Layer
                if packet.haslayer(scapy.TCP):
                    packet_info["Headers"]["TCP"] = {
                        "Source Port": packet[scapy.TCP].sport,
                        "Destination Port": packet[scapy.TCP].dport,
                        "Sequence Number": packet[scapy.TCP].seq,
                        "Acknowledgment Number": packet[scapy.TCP].ack,
                        "Flags": str(packet[scapy.TCP].flags),
                    }

                # UDP Layer
                if packet.haslayer(scapy.UDP):
                    packet_info["Headers"]["UDP"] = {
                        "Source Port": packet[scapy.UDP].sport,
                        "Destination Port": packet[scapy.UDP].dport,
                        "Length": packet[scapy.UDP].len,
                    }

                # ICMP Layer
                if packet.haslayer(scapy.ICMP):
                    packet_info["Headers"]["ICMP"] = {
                        "Type": packet[scapy.ICMP].type,
                       # "Code": packet[scapy.ICMP].code,
                        "Checksum": packet[scapy.ICMP].chksum,
                    }

                # Application Layer (Raw Payload)
               # if packet.haslayer(scapy.Raw):
                #    packet_info["Headers"]["Raw Payload"] = packet[scapy.Raw].load.hex()

                ip_packets_list.append(packet_info)

    return render_template("ip_packets.html", ip_address=ip_address, ip_packets=ip_packets_list)


import pyshark

from scapy.all import rdpcap, TCP
from scapy.layers.http import HTTPRequest, HTTPResponse

def extract_http_headers(pcap_file):
    try:
        packets = rdpcap(pcap_file)  # Read the PCAP file
        http_packets = []

        for pkt in packets:
            if pkt.haslayer(HTTPRequest):  # Check for HTTP Request
                http_layer = pkt[HTTPRequest]
                http_packets.append({
                    "method": http_layer.Method.decode(),
                    "host": http_layer.Host.decode() if http_layer.Host else "N/A",
                    "uri": http_layer.Path.decode() if http_layer.Path else "N/A",
                    "user_agent": http_layer.User_Agent.decode() if http_layer.User_Agent else "N/A",
                    "request_headers": str(http_layer)
                })

            elif pkt.haslayer(HTTPResponse):  # Check for HTTP Response
                http_layer = pkt[HTTPResponse]
                http_packets.append({
                    "response_code": http_layer.Status_Code.decode() if http_layer.Status_Code else "N/A",
                    "response_headers": str(http_layer)
                })

        print("Extracted HTTP Packets:", http_packets)  # Debugging
        return http_packets

    except Exception as e:
        print(f"Error processing packet: {e}")
        return []
        
# Define known vulnerable and legitimate ports
VULNERABLE_PORTS = {21, 23, 25,80, 110, 139, 143, 3306, 3389, 5900}
LEGITIMATE_PORTS = {53, 443, 993, 995, 1433, 1521}

def analyze_ports(associated_ips):
    suspicious_ports = set()
    legitimate_ports = set()

    for ip, details in associated_ips.items():
        for port in details["src_ports"] | details["dst_ports"]:  # Check both source and destination ports
            port = int(port) if str(port).isdigit() else None  # Ensure it's a valid integer
            if port:
                if port in VULNERABLE_PORTS:
                    suspicious_ports.add(port)
                elif port in LEGITIMATE_PORTS:
                    legitimate_ports.add(port)

    return sorted(legitimate_ports), sorted(suspicious_ports)

@app.route('/dashboard/<selected_ip>')
def dashboard(selected_ip):
    df = pd.DataFrame(session.get('filtered_data', []))
    associated_ips = {}

    ip_type = request.args.get('ip_type', '')

    if ip_type == 'src':
        for _, row in df.iterrows():
            if row["Source IP"] == selected_ip:
                dst_ip = row["Destination IP"]
                protocol = row["Protocol"]
                src_port = row["Source Port"]
                dst_port = row["Destination Port"]

                if dst_ip not in associated_ips:
                    associated_ips[dst_ip] = {"protocols": set(), "src_ports": set(), "dst_ports": set()}

                associated_ips[dst_ip]["protocols"].add(protocol)
                associated_ips[dst_ip]["src_ports"].add(src_port)
                associated_ips[dst_ip]["dst_ports"].add(dst_port)

    elif ip_type == 'dst':
        for _, row in df.iterrows():
            if row["Destination IP"] == selected_ip:
                src_ip = row["Source IP"]
                protocol = row["Protocol"]
                src_port = row["Source Port"]
                dst_port = row["Destination Port"]

                if src_ip not in associated_ips:
                    associated_ips[src_ip] = {"protocols": set(), "src_ports": set(), "dst_ports": set()}

                associated_ips[src_ip]["protocols"].add(protocol)
                associated_ips[src_ip]["src_ports"].add(src_port)
                associated_ips[src_ip]["dst_ports"].add(dst_port)

    # ✅ New Feature: Analyze Ports
    legitimate_ports, suspicious_ports = analyze_ports(associated_ips)

    return render_template('dashboard.html', 
                           selected_ip=selected_ip, 
                           associated_ips=associated_ips,
                           legitimate_ports=legitimate_ports,
                           suspicious_ports=suspicious_ports)

        


from flask import Flask, render_template
from modules.http_analysis import extract_http_headers

from flask import Flask, render_template
from modules.http_analysis import extract_http_data
import os


PCAP_FILE = "uploads/sample.pcap"

@app.route('/http-analysis')
def http_analysis():
    """Renders HTTP Analysis Page"""
    if not os.path.exists(PCAP_FILE):
        return render_template('http_analysis.html', packets=[], stats={})

    http_packets = extract_http_data(PCAP_FILE)

    method_counts = {}
    status_counts = {}

    for packet in http_packets:
        method = packet["Method"] if packet["Method"] not in ["Unknown", "N/A"] else "Other"
        status = packet["Status Code"] if packet["Status Code"].isdigit() else "Unknown"

        method_counts[method] = method_counts.get(method, 0) + 1
        status_counts[status] = status_counts.get(status, 0) + 1

    stats = {
        "method_counts": method_counts,
        "status_counts": status_counts
}

    return render_template('http_analysis.html', packets=http_packets, stats=stats)



from flask import Flask, render_template, jsonify
from modules.http_analysis import extract_http_data  # Import correctly
from collections import Counter


DNS_TYPE_MAP = {
    "1": "A",
    "2": "NS",
    "5": "CNAME",
    "6": "SOA",
    "12": "PTR",
    "15": "MX",
    "16": "TXT",
    "28": "AAAA",
    "33": "SRV",
    "255": "ANY"
}

def extract_dns_data(pcap_file):
    dns_data = []
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter="dns")
        for packet in cap:
            if hasattr(packet, "dns"):
                dns_query = getattr(packet.dns, "qry_name", "N/A")
                dns_type_code = getattr(packet.dns, "qry_type", "N/A")
                dns_type = DNS_TYPE_MAP.get(str(dns_type_code), f"Unknown ({dns_type_code})")

                
                # Extract possible DNS responses
                dns_response = getattr(packet.dns, "a", None)  
                cname_response = getattr(packet.dns, "cname", None)  
                aaaa_response = getattr(packet.dns, "aaaa", None)  
                mx_response = getattr(packet.dns, "mx", None)  
                
                response_list = []
                if dns_response:
                    response_list.append(f"A: {dns_response}")
                if cname_response:
                    response_list.append(f"CNAME: {cname_response}")
                if aaaa_response:
                    response_list.append(f"AAAA: {aaaa_response}")
                if mx_response:
                    response_list.append(f"MX: {mx_response}")

                response_text = ", ".join(response_list) if response_list else "N/A"

                # Extract IP addresses
                src_ip = getattr(packet.ip, "src", "N/A") if hasattr(packet, "ip") else "N/A"
                dst_ip = getattr(packet.ip, "dst", "N/A") if hasattr(packet, "ip") else "N/A"

                dns_data.append({
                    "Source IP": src_ip,
                    "Destination IP": dst_ip,
                    "Query": dns_query,
                    "Type": dns_type,
                    "Response": response_text
                })
        cap.close()
    except Exception as e:
        print(f"Error processing PCAP file: {e}")
    return dns_data
        

# Extract DNS Stats for Pie Charts (New function)
def extract_dns_stats(pcap_file):
    dns_protocols = Counter()
    dns_failures = Counter()
    country_distribution = Counter()

    try:
        cap = pyshark.FileCapture(pcap_file, display_filter="dns")
        for packet in cap:
            if hasattr(packet.dns, "qry_name"):
                query_name = packet.dns.qry_name
                dns_protocols["DNS"] += 1  # Assume DNS protocol usage

                # Fake country classification (replace with GeoIP lookup if needed)
                if ".in" in query_name:
                    country_distribution["India"] += 1
                elif ".us" in query_name:
                    country_distribution["USA"] += 1
                else:
                    country_distribution["Other"] += 1


        cap.close()
    except Exception as e:
        print(f"Error processing DNS stats: {e}")

    return {
        "dns_protocols": dict(dns_protocols),
        "country_distribution": dict(country_distribution)
    }

# Route to Fetch DNS Table + Pie Chart Stats
from collections import Counter

@app.route("/dns-analysis")
def dns_analysis():
    pcap_file = session.get("uploaded_pcap", "uploads/sample.pcap")
    dns_data = extract_dns_data(pcap_file)

    # Count occurrences of each DNS Type
    dns_type_counts = Counter(entry["Type"] for entry in dns_data)

    return render_template("dns_analysis.html", dns_data=dns_data, dns_type_counts=dns_type_counts)


# API to Fetch DNS Stats for Pie Charts
@app.route('/dns_stats')
def get_dns_stats():
    pcap_file = session.get("uploaded_pcap", "uploads/sample.pcap")
    stats = extract_dns_stats(pcap_file)
    return jsonify(stats)
    
    
    
import pyshark
from flask import Flask, render_template, jsonify, session

def extract_icmp_data(pcap_file):
    icmp_data = []
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter="icmp")
        for packet in cap:
            if hasattr(packet, "icmp"):
                icmp_type = getattr(packet.icmp, "type", "N/A")
                icmp_code = getattr(packet.icmp, "code", "N/A")
                ttl = getattr(packet.ip, "ttl", "N/A") if hasattr(packet, "ip") else "N/A"
                sequence_number = getattr(packet.icmp, "seq", "N/A")
                timestamp = getattr(packet.frame_info, "time", "N/A")

                src_ip = getattr(packet.ip, "src", "N/A") if hasattr(packet, "ip") else "N/A"
                dst_ip = getattr(packet.ip, "dst", "N/A") if hasattr(packet, "ip") else "N/A"

                icmp_data.append({
                    "Source IP": src_ip,
                    "Destination IP": dst_ip,
                    "Type": icmp_type,
                    "Code": icmp_code,
                    "TTL": ttl,
                    "Sequence Number": sequence_number,
                    "Timestamp": timestamp
                })
        cap.close()
    except Exception as e:
        print(f"Error processing ICMP packets: {e}")

    return icmp_data

@app.route("/icmp-analysis")
def icmp_analysis():
    pcap_file = session.get("uploaded_pcap", "uploads/sample.pcap")
    icmp_data = extract_icmp_data(pcap_file)

    return render_template("icmp_analysis.html", icmp_data=icmp_data)

@app.route("/icmp_stats")
def icmp_stats():
    pcap_file = session.get("uploaded_pcap", "uploads/sample.pcap")
    icmp_data = extract_icmp_data(pcap_file)

    icmp_types_count = {}
    for entry in icmp_data:
        icmp_type = entry["Type"]
        icmp_types_count[icmp_type] = icmp_types_count.get(icmp_type, 0) + 1

    return jsonify({"icmp_types": icmp_types_count})
    
    
    
from flask import Flask, render_template, jsonify
import pyshark


# Function to extract FTP data from PCAP
def get_ftp_data():
    pcap_file = "uploads/sample.pcap"  # Change this to your PCAP file path
    ftp_data = []
    
    capture = pyshark.FileCapture(pcap_file, display_filter="ftp")
    
    for packet in capture:
        try:
            source_ip = packet.ip.src
            dest_ip = packet.ip.dst
            command = packet.ftp.request_command if hasattr(packet.ftp, "request_command") else "N/A"
            response_code = packet.ftp.response_code if hasattr(packet.ftp, "response_code") else "N/A"
            file_name = packet.ftp.request_arg if hasattr(packet.ftp, "request_arg") else "N/A"
            status = "Success" if response_code.startswith("2") else "Failed"
            
            ftp_data.append({
                "Source IP": source_ip,
                "Destination IP": dest_ip,
                "Command": command,
                "Response Code": response_code,
                "File Name": file_name,
                "Status": status
            })
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    capture.close()
    return ftp_data

# Function to calculate FTP statistics
def get_ftp_stats():
    ftp_data = get_ftp_data()
    ftp_commands = {}
    ftp_responses = {}

    for entry in ftp_data:
        command = entry["Command"]
        response = entry["Response Code"]

        if command != "N/A":
            ftp_commands[command] = ftp_commands.get(command, 0) + 1
        if response != "N/A":
            ftp_responses[response] = ftp_responses.get(response, 0) + 1

    return {"ftp_commands": ftp_commands, "ftp_responses": ftp_responses}

# Route for FTP Analysis page
@app.route('/ftp-analysis')
def ftp_analysis():
    ftp_data = get_ftp_data()
    return render_template('ftp_analysis.html', ftp_data=ftp_data)

# Route to fetch FTP statistics for charts
@app.route('/ftp_stats')
def ftp_stats():
    return jsonify(get_ftp_stats())

    
from flask import Flask, render_template
import pyshark
from collections import Counter





from flask import Flask, render_template
from collections import Counter
import pyshark


PCAP_FILE = "uploads/sample.pcap"   # Update to your actual PCAP path


def interpret_tcp_flags(flag_hex):
    flags_int = int(flag_hex, 16)
    interpretations = []
    if flags_int & 0x01:
        interpretations.append("FIN")
    if flags_int & 0x02:
        interpretations.append("SYN")
    if flags_int & 0x04:
        interpretations.append("RST")
    if flags_int & 0x08:
        interpretations.append("PSH")
    if flags_int & 0x10:
        interpretations.append("ACK")
    if flags_int & 0x20:
        interpretations.append("URG")
    if flags_int & 0x40:
        interpretations.append("ECE")
    if flags_int & 0x80:
        interpretations.append("CWR")
    return ', '.join(interpretations)


def extract_tcp_data():
    tcp_entries = []
    tcp_flags_counter = Counter()
    tcp_port_counter = Counter()

    try:
        cap = pyshark.FileCapture(PCAP_FILE, display_filter="tcp", keep_packets=False)

        for packet in cap:
            try:
                # Include only TCP packets that do NOT contain higher-layer protocols
                layers = [layer.layer_name for layer in packet.layers]
                if any(proto in layers for proto in ['http', 'ssl', 'dns', 'ftp']):
                    continue

                frame_number = packet.frame_info.number
                src_ip = packet.ip.src
                dest_ip = packet.ip.dst
                src_port = packet.tcp.srcport
                dest_port = packet.tcp.dstport
                seq_num = packet.tcp.seq
                ack_num = packet.tcp.ack
                window_size = packet.tcp.window_size
                flags = packet.tcp.flags

                interpreted_flags = interpret_tcp_flags(flags)

                tcp_entries.append({
                    "frame_number": frame_number,
                    "src_ip": src_ip,
                    "dest_ip": dest_ip,
                    "src_port": src_port,
                    "dest_port": dest_port,
                    "seq_num": seq_num,
                    "ack_num": ack_num,
                    "window_size": window_size,
                    "flags": interpreted_flags
                })

                tcp_flags_counter[interpreted_flags] += 1
                tcp_port_counter[dest_port] += 1

            except AttributeError:
                continue

        cap.close()
    except Exception as e:
        print(f"Error processing TCP packets: {e}")

    return tcp_entries, dict(tcp_flags_counter), dict(tcp_port_counter)


@app.route('/tcp-analysis')
def tcp_analysis():
    tcp_entries, tcp_flags_distribution, tcp_port_distribution = extract_tcp_data()
    return render_template(
        "tcp_analysis.html",
        tcp_entries=tcp_entries,
        tcp_flags_distribution=tcp_flags_distribution,
        tcp_port_distribution=tcp_port_distribution
    )




if __name__ == '__main__':
    app.run(debug=True)

