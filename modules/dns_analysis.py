import subprocess
import json

def extract_dns_info(pcap_file):
    """
    Extracts DNS query and response details from a PCAP file using TShark.
    """
    try:
        # Run TShark command to get DNS queries and responses
        tshark_cmd = [
            "tshark", "-r", pcap_file, "-Y", "dns",
            "-T", "json", "-e", "dns.qry.name", "-e", "dns.a",
            "-e", "dns.resp.name", "-e", "dns.resp.addr"
        ]
        result = subprocess.run(tshark_cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise Exception(f"TShark Error: {result.stderr}")

        dns_data = json.loads(result.stdout) if result.stdout else []

        extracted_data = []
        for packet in dns_data:
            fields = packet.get("_source", {}).get("layers", {}).get("dns", {})

            extracted_data.append({
                "query": fields.get("dns.qry.name", ["N/A"])[0],
                "response": fields.get("dns.resp.name", ["N/A"])[0],
                "ip": fields.get("dns.a", ["N/A"])[0]
            })

        return extracted_data

    except Exception as e:
        return {"error": str(e)}
