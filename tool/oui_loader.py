import csv
from pathlib import Path


def normalize_oui_prefix(raw: str) -> str:

    s = raw.strip().upper()
    for ch in ("-", ":", "."):
        s = s.replace(ch, "")
    return s[:6]


def load_oui_csv(path: Path) -> dict[str, str]:

    mapping: dict[str, str] = {}

    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        prefix_keys = ["Assignment", "Registry Assignment", "OUI"]
        vendor_keys = ["Organization Name", "Organization", "Vendor"]

        for row in reader:
            prefix = ""
            vendor = ""

            for key in prefix_keys:
                if key in row and row[key]:
                    prefix = row[key]
                    break

            for key in vendor_keys:
                if key in row and row[key]:
                    vendor = row[key].strip()
                    break

            if not prefix or not vendor:
                continue

            normalized = normalize_oui_prefix(prefix)
            if len(normalized) != 6:
                continue

            mapping[normalized] = vendor

    return mapping


def lookup_vendor(mac_address: str, oui_map: dict[str, str]) -> str:

    prefix = normalize_oui_prefix(mac_address)
    return oui_map.get(prefix, "")


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent
    csv_path = base_dir / "input" / "oui.csv"

    oui_map = load_oui_csv(csv_path)

    print(f"[OK] loaded {len(oui_map)} OUI entries from {csv_path}")

    samples = [
        "00:1A:2B:11:22:33",
        "AA-BB-CC-44-55-66",
    ]

    for mac in samples:
        vendor = lookup_vendor(mac, oui_map)
        print(f"{mac} -> {vendor or '(unknown)'}")