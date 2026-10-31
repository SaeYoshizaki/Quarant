#!/usr/bin/env python3
"""Check that every quote in a claims TSV appears verbatim in its saved snapshot.

Usage: check_quotes.py <snapshots dir> <claims.tsv>...

A snapshot file's first line is "SOURCE <archive url>"; rows are matched to
files by that URL. Whitespace is normalised and typographic quotes and dashes
are folded before comparing. "***" in a quote stands for a masked value (a
credential written in the source) and matches any short text. Prints every row
that does not match.
"""
import csv
import re
import sys
from pathlib import Path

FOLD = str.maketrans({"’": "'", "‘": "'", "“": '"', "”": '"', "–": "-", "—": "-", " ": " "})


def norm(s):
    return re.sub(r"\s+", " ", s.translate(FOLD)).strip().lower()


def found(quote, bodies):
    q = norm(quote)
    if "***" not in q:
        return any(q in b for b in bodies)
    pattern = re.compile(r"[^ ]{0,40}".join(re.escape(part) for part in q.split("***")))
    return any(pattern.search(b) for b in bodies)


def main():
    snaps = {}
    for f in Path(sys.argv[1]).glob("*.txt"):
        first, _, body = f.read_text(errors="ignore").partition("\n")
        url = first.removeprefix("SOURCE ").strip().replace("id_/", "/")
        snaps.setdefault(url, []).append(norm(body))
    bad = total = 0
    for tsv in sys.argv[2:]:
        for r in csv.DictReader(open(tsv), delimiter="\t"):
            q = r["quote"]
            if q.startswith("("):
                continue
            total += 1
            bodies = snaps.get(r["url"].strip())
            if not bodies:
                bad += 1
                print(f"NO SNAPSHOT\t{tsv}\t{r['product']}\t{r['url']}")
            elif not found(q, bodies):
                bad += 1
                print(f"NOT FOUND\t{tsv}\t{r['product']}\t{q[:80]}")
    print(f"checked {total}, problems {bad}")


if __name__ == "__main__":
    main()
