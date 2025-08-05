from scapy.all import rdpcap, TCP
from scapy.layers.http import HTTPRequest, HTTPResponse

def extract_http_headers(pcap_file):
    http_packets = []
    
    # Read the PCAP file
    packets = rdpcap(pcap_file)
    
    for packet in packets:
        if packet.haslayer(TCP) and (packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse)):
            parsed_data = parse_http_packet(packet)
            if parsed_data:
                http_packets.append(parsed_data)

    return http_packets
import pyshark

def extract_http_data(pcap_file):
    http_packets = []
    try:
        capture = pyshark.FileCapture(pcap_file, display_filter="http")
        for packet in capture:
            try:
                http_layer = packet.http
                http_packets.append({
                    "Method": getattr(http_layer, 'request_method', 'Unknown'),
                    "Host": getattr(http_layer, 'host', 'Unknown'),
                    "URI": getattr(http_layer, 'request_uri', 'Unknown'),
                    "User-Agent": getattr(http_layer, 'user_agent', 'Unknown'),
                    "Content-Type": getattr(http_layer, 'content_type', 'Unknown'),
                    "Content-Length": getattr(http_layer, 'content_length', 'Unknown'),
                    "Status Code": getattr(http_layer, 'response_code', 'Unknown'),
                    "Headers": '\n'.join([str(f) for f in http_layer._all_fields.values()])
                })
            except AttributeError:
                continue
        capture.close()
    except Exception as e:
        print(f"Error processing PCAP: {e}")
    return http_packets

from scapy.all import TCP
from scapy.layers.http import HTTPRequest, HTTPResponse

def parse_http_packet(packet):
    """
    Parses HTTP request and response packets and extracts headers correctly.
    """
    http_data = {}

    if packet.haslayer(HTTPRequest):  # If it's an HTTP request
        http_layer = packet[HTTPRequest]
        http_data = {
            "method": http_layer.Method.decode() if http_layer.Method else "N/A",
            "host": http_layer.Host.decode() if http_layer.Host else "N/A",
            "uri": http_layer.Path.decode() if http_layer.Path else "N/A",
            "user_agent": http_layer.User_Agent.decode() if http_layer.User_Agent else "N/A",
            "content_type": http_layer.Content_Type.decode() if http_layer.Content_Type else "N/A",
            "content_length": http_layer.Content_Length.decode() if http_layer.Content_Length else "N/A",
            "status_code": "N/A",  # Requests don't have a status code
            "headers": str(http_layer)
        }
    
    elif packet.haslayer(HTTPResponse):  # If it's an HTTP response
        http_layer = packet[HTTPResponse]
        http_data = {
            "method": "HTTP Response",  # Change from "Response" to "HTTP Response"
            "host": "N/A",
            "uri": "N/A",
            "user_agent": "N/A",
            "content_type": http_layer.Content_Type.decode() if http_layer.Content_Type else "N/A",
            "content_length": http_layer.Content_Length.decode() if http_layer.Content_Length else "N/A",
            "status_code": http_layer.Status_Code.decode() if http_layer.Status_Code else "N/A",
            "headers": str(http_layer)
        }

    return http_data if http_data else None

