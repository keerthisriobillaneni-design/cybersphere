import json, csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data" / "enterprise-attack.json"
OUT = ROOT / "data" / "attack_techniques.csv"

def main():
    if not SOURCE.exists():
        raise SystemExit("ATT&CK file not found. Run: python src/download_attack.py")
    bundle = json.loads(SOURCE.read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])
    techniques = []
    groups = []
    for obj in objects:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False):
            external_ids = [
                ref.get("external_id") for ref in obj.get("external_references", [])
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id")
            ]
            techniques.append({
                "technique_id": external_ids[0] if external_ids else "",
                "name": obj.get("name", ""),
                "description": (obj.get("description", "") or "").replace("\n", " ")[:500],
                "domain": ";".join(obj.get("x_mitre_domains", []))
            })
        elif obj.get("type") == "intrusion-set" and not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False):
            groups.append({"group_name": obj.get("name", ""), "description": (obj.get("description", "") or "").replace("\n", " ")[:500]})
    with OUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["technique_id", "name", "description", "domain"])
        writer.writeheader()
        writer.writerows(techniques)
    group_out = ROOT / "data" / "attack_groups.csv"
    with group_out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["group_name", "description"])
        writer.writeheader()
        writer.writerows(groups)
    print(f"Exported {len(techniques)} techniques to {OUT}")
    print(f"Exported {len(groups)} groups to {group_out}")
    print("Note: this exports objects only; it does not yet connect actors to techniques using STIX relationship objects.")

if __name__ == "__main__":
    main()
