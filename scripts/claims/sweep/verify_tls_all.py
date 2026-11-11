#!/usr/bin/env python3
"""Run verify.py tls for the TLS candidates and collect the output.

usage: verify_tls_all.py <devices.tsv> <candidates.tsv> <out.txt> <capture root>... [--only <vendor product>]...

For each tls-* candidate, the first evidence (dataset:file#frame) whose capture file is found under
one of the roots is opened. Candidates without a capture at hand are listed as skipped.
"""
import collections
import csv
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from verify_all import finder, path_of  # noqa: E402


def main():
    args, only = [], []
    it = iter(sys.argv[1:])
    for a in it:
        if a == "--only":
            only.append(next(it))
        else:
            args.append(a)
    devices_tsv, cand, out, *roots = args
    index = finder(roots)
    devs = collections.defaultdict(dict)
    for r in csv.DictReader(open(devices_tsv), delimiter="\t"):
        devs[(r["vendor"], " ".join(x for x in (r["product"], r["model"]) if x) or r["label"])][r["dataset"]] = r["mac"].lower()
    rows = [r for r in csv.DictReader(open(cand), delimiter="\t", quoting=csv.QUOTE_NONE) if r["kind"].startswith("tls")]
    if only:
        rows = [r for r in rows if f'{r["vendor"]} {r["product"]}' in only]
    with open(out, "w") as o:
        for r in rows:
            head = f'### {r["vendor"]} {r["product"]} | {r["kind"]} | {r["detail"][:160]}'
            done = False
            for ev in r["evidence"].split("; "):
                ds, _, rest = ev.partition(":")
                name, _, frame = rest.rpartition("#")
                mac = devs[(r["vendor"], r["product"])].get(ds)
                p = path_of(index, ds, name)
                if not (mac and p):
                    continue
                res = subprocess.run([sys.executable, str(HERE / "verify.py"), "tls", p, mac, frame], capture_output=True, text=True)
                o.write(f"{head}\n  evidence {ev}\n{res.stdout}{res.stderr[-300:]}\n")
                o.flush()
                done = True
                break
            if not done:
                o.write(head + "\n  skipped: no capture at hand that holds it\n\n")
            print(head[:100], "done" if done else "skipped", flush=True)


if __name__ == "__main__":
    main()
