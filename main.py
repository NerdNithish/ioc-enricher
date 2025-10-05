# main.py
import requests
import json
import pandas as pd
import time
import argparse
import os
from dotenv import load_dotenv

load_dotenv()  # load environment variables from .env
API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

def handle_response(response):
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 429:
        print("[!] Rate limit hit — sleeping 15s...")
        time.sleep(15)
        return None
    elif response.status_code == 403:
        print("[!] Forbidden — check your API key permissions.")
        return None
    else:
        print(f"[!] HTTP {response.status_code}: {response.text}")
        return None

def enrich_ip(ip):
    url = f"{BASE_URL}/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        data = handle_response(response)
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        result = {
            "ip": ip,
            "malicious_votes": attrs.get("last_analysis_stats", {}).get("malicious", 0),
            "last_analysis_date": attrs.get("last_analysis_date", "N/A")
        }
        return result
    except Exception as e:
        return {"ip": ip, "error": str(e)}
    
def enrich_domain(domain):
    url = f"{BASE_URL}/domains/{domain}"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        data = handle_response(response)
        if not data:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        result = {
            "domain": domain,
            "malicious_votes": attrs.get("last_analysis_stats", {}).get("malicious", 0),
            "last_analysis_date": attrs.get("last_analysis_date", "N/A"),
            "registrar": attrs.get("registrar", "N/A"),
            "country": attrs.get("country", "N/A")
        }
        return result
    except Exception as e:
        return {"domain": domain, "error": str(e)}
    
def process_list(iocs, out_csv="enriched_iocs.csv"):
    results = []
    for idx, ip in enumerate(iocs, 1):
        ip = ip.strip()
        if not ip:
            continue
        print(f"[{idx}/{len(iocs)}] Enriching {ip} ...")
        res = enrich_ip(ip)
        if res:
            results.append(res)
        time.sleep(15)  # be polite with free API tier
    import pandas as pd
    df = pd.DataFrame(results)
    df.to_csv(out_csv, index=False)
    print(f"Saved {len(results)} results to {out_csv}")
    return df

def main():
    parser = argparse.ArgumentParser(description="Simple IOC Enricher with VirusTotal")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="Single IP to enrich")
    group.add_argument("--domain", help="Single domain to enrich")
    group.add_argument("--file", help="File containing IOCs (one per line)")

    args = parser.parse_args()

    if args.ip:
        result = enrich_ip(args.ip)
        if result:
            print(result)
            df = pd.DataFrame([result])
            df.to_csv("enriched_iocs.csv", index=False)

    elif args.domain:
        result = enrich_domain(args.domain)
        if result:
            print(result)
            df = pd.DataFrame([result])
            df.to_csv("enriched_iocs.csv", index=False)

    elif args.file:
        with open(args.file) as f:
            iocs = f.readlines()
        process_list(iocs)

# Example usage
if __name__ == "__main__":
    main()
