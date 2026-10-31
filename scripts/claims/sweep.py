#!/usr/bin/env python3
"""List security-related sentences in saved snapshots that claims.tsv does not cover.

Usage: sweep.py <snapshots dir> <claims.tsv> <out.tsv>

Tier A sentences (technical words) are all reviewed by hand; tier B (general
words such as security or privacy) are reviewed by sampling.

For every snapshot that claims.tsv cites (by its SOURCE url), split the text into
sentences, keep those containing a security keyword, and drop the ones that a
quoted claim already covers (one contains the other after normalisation). The
remaining sentences are candidates for missed claims and are checked by hand.
The output holds vendor text, so keep it outside the repository.
"""
import csv
import re
import sys
from pathlib import Path

# Tier A: technical words that usually carry a checkable claim; every hit is reviewed.
TIER_A = re.compile(
    r"\b(encrypt\w*|ssl|tls|https|aes|rsa|cipher\w*|certificate\w*|password\w*|passcode|credential\w*|"
    r"authenticat\w*|two-step|two-factor|2fa|firmware|software updates?|automatic(?:ally)? updat\w*|"
    r"over-the-air|signed|signature|end-to-end|hash\w*)\b", re.I)
# Tier B: general words (security, protect, privacy); reviewed by sampling.
TIER_B = re.compile(r"\b(secur(?!ifi)\w*|protect\w*|privacy|hack\w*|vulnerab\w*)\b", re.I)
FOLD = str.maketrans({"’": "'", "‘": "'", "“": '"', "”": '"', "–": "-", "—": "-", " ": " "})


def norm(s):
    return re.sub(r"\s+", " ", s.translate(FOLD)).strip().lower()


def sentences(text):
    for block in text.splitlines():
        for s in re.split(r"(?<=[.!?])\s+", block):
            s = s.strip()
            if 25 <= len(s) <= 600:
                yield s


def main():
    snaps_dir, claims_tsv, out = sys.argv[1:4]
    rows = list(csv.DictReader(open(claims_tsv), delimiter="\t"))
    quotes = {}
    products = {}
    for r in rows:
        quotes.setdefault(r["url"], []).append(norm(r["quote"]))
        products.setdefault(r["url"], set()).add(r["product"])
    n = 0
    with open(out, "w", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["url", "products", "tier", "keyword", "sentence"])
        for path in sorted(Path(snaps_dir).glob("*.txt")):
            first, _, body = path.read_text(errors="ignore").partition("\n")
            url = first.removeprefix("SOURCE ").strip().replace("id_/", "/")
            if url not in quotes:
                continue
            seen = set()
            for s in sentences(body):
                m = TIER_A.search(s)
                tier = "A"
                if not m:
                    m, tier = TIER_B.search(s), "B"
                ns = norm(s)
                if not m or ns in seen:
                    continue
                seen.add(ns)
                if any(q in ns or ns in q for q in quotes[url] if len(q) > 15):
                    continue
                w.writerow([url, ", ".join(sorted(products[url])), tier, m.group(0).lower(), s])
                n += 1
    print(f"{n} uncovered sentences")


if __name__ == "__main__":
    main()
