from pathlib import Path
import requests

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "enterprise-attack.json"
URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

def main():
    print("Downloading official MITRE ATT&CK Enterprise STIX 2.1 data...")
    response = requests.get(URL, timeout=90)
    response.raise_for_status()
    OUT.write_bytes(response.content)
    print(f"Saved {OUT}")
    print(f"Size: {OUT.stat().st_size:,} bytes")

if __name__ == "__main__":
    main()
