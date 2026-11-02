#!/usr/bin/env python3
"""Wayback Machine helper (rate-limited, one request at least every 5 s across processes).

  wb.py cdx <url pattern> [from] [to] [mime]   list archived captures (mime: text/html default, any)
  wb.py fetch <timestamp> <url> <name>         save the raw capture under ~/datasets/claims/snapshots/
                                               as <name>-<timestamp>.txt (first line SOURCE <archive url>);
                                               HTML is turned into text, PDF via pdftotext, JSON kept as is
"""
import fcntl
import gzip
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

LOCK = Path.home() / "datasets/claims/jobs/wb.lock"
LOCK.parent.mkdir(parents=True, exist_ok=True)
SNAP = Path.home() / "datasets/claims/snapshots"


def get(url):
    with open(LOCK, "a+") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        lk.seek(0)
        last = float(lk.read() or 0)
        wait = 5 - (time.time() - last)
        if wait > 0:
            time.sleep(wait)
        for attempt in range(4):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "research (claims check)"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    data, ctype = r.read(), r.headers.get("Content-Type", "")
                    if r.headers.get("Content-Encoding") == "gzip" or data[:2] == b"\x1f\x8b":
                        data = gzip.decompress(data)
                break
            except Exception as e:  # rate limiting or transient errors
                err = e
                time.sleep(10 * (attempt + 1))
        else:
            raise SystemExit(f"failed: {url}: {err}")
        lk.seek(0)
        lk.truncate()
        lk.write(str(time.time()))
    return data, ctype


def text_of(data, ctype):
    if data[:4] == b"%PDF" or "pdf" in ctype:
        p = subprocess.run(["pdftotext", "-layout", "-", "-"], input=data, capture_output=True)
        return p.stdout.decode("utf-8", "replace"), data
    t = data.decode("utf-8", "replace")
    if "json" in ctype or t.lstrip()[:1] in "{[":
        return t, None
    t = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", t)
    t = re.sub(r"(?i)<br\s*/?>|</(p|div|li|h\d|tr|section|article)>", "\n", t)
    t = html.unescape(re.sub(r"<[^>]+>", " ", t))
    lines = [re.sub(r"[ \t]+", " ", x).strip() for x in t.splitlines()]
    return "\n".join(x for x in lines if x), None


def main():
    cmd = sys.argv[1]
    if cmd == "cdx":
        pat = sys.argv[2]
        frm = sys.argv[3] if len(sys.argv) > 3 else "2016"
        to = sys.argv[4] if len(sys.argv) > 4 else "2019"
        mime = sys.argv[5] if len(sys.argv) > 5 else "text/html"
        q = {"url": pat, "from": frm, "to": to, "output": "json", "fl": "timestamp,original,statuscode,mimetype",
             "collapse": "digest", "limit": "2000"}
        if mime != "any":
            q["filter"] = f"mimetype:{mime}"
        data, _ = get("https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(q))
        rows = json.loads(data or b"[]")
        for r in rows[1:]:
            print(r[0], r[1], r[2], r[3])
    elif cmd == "fetch":
        ts, url, name = sys.argv[2:5]
        data, ctype = get(f"https://web.archive.org/web/{ts}id_/{url}")
        text, pdf = text_of(data, ctype)
        SNAP.mkdir(parents=True, exist_ok=True)
        out = SNAP / f"{name}-{ts}.txt"
        if pdf:
            (SNAP / f"{name}-{ts}.pdf").write_bytes(pdf)
        out.write_text(f"SOURCE https://web.archive.org/web/{ts}/{url}\n{text}")
        print(out, len(text.splitlines()))


if __name__ == "__main__":
    main()
