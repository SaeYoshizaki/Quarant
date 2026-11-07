#!/usr/bin/env python3
"""Was each candidate claim still published around the capture (2018-03-20..04-19)?

Usage: triage_docs.py <claims.tsv> <row numbers, comma separated> <out.tsv>

For each claims.tsv row (header = row 1): list the archived captures of the same URL, fetch the last one
before 2018-03-20 and the first one after 2018-04-19, and check whether the quoted sentence is on them.
Uses wb.py (rate-limited). Prints only dates and yes/no.
"""
import csv, re, subprocess, sys
from pathlib import Path
WB = [sys.executable, '-I', str(Path(__file__).with_name('wb.py'))]
csv.field_size_limit(10**8)
def norm(s): return re.sub(r'[^a-z0-9]+', ' ', s.lower()).strip()
def present(quote, text):
    q, t = norm(quote), norm(text)
    if not q: return 'no-quote'
    if q[:90] in t: return 'yes'
    w = q.split()
    wins = [' '.join(w[i:i+6]) for i in range(0, max(len(w)-5, 1), max(len(w)//4, 1))][:4]
    hit = sum(1 for x in wins if x in t)
    return 'yes' if hit >= max(2, len(wins)-1) else ('partly' if hit else 'no')
def run(args):
    p = subprocess.run(WB + args, capture_output=True, text=True)
    return p.stdout
rows = list(csv.DictReader(open(sys.argv[1]), delimiter='\t'))
want = [int(x) for x in sys.argv[2].split(',')]
out = open(sys.argv[3], 'w')
out.write('row\tproduct\tread_snapshot\tlast_before\tpresent_before\tfirst_after\tpresent_after\tcaptures_2017_2018\n')
for n in want:
    r = rows[n-2]
    m = re.match(r'https?://web\.archive\.org/web/(\d+)[a-z_]*/(.+)', r['url'])
    if not m:
        out.write(f"{n}\t{r['product']}\t{r['snapshot']}\tno-wayback-url\t\t\t\t\n"); continue
    orig = m.group(2)
    caps = []
    for line in run(['cdx', orig, '2016', '2019', 'any']).splitlines():
        a = line.split()
        if len(a) >= 3 and a[2] == '200': caps.append(a[0])
    caps = sorted(set(caps))
    before = [c for c in caps if c < '20180320']; after = [c for c in caps if c > '20180419']
    res = []
    for c in ([before[-1]] if before else []) + ([after[0]] if after else []):
        line = run(['fetch', c, orig, f'triage-row{n}']).strip().splitlines()
        path = line[-1].split()[0] if line else ''
        txt = Path(path).read_text(errors='replace') if path and Path(path).exists() else ''
        res.append((c, present(r['quote'], txt) if txt else 'fetch-failed'))
    b = res[0] if before else ('', '')
    a_ = res[-1] if after else ('', '')
    out.write(f"{n}\t{r['product']}\t{r['snapshot']}\t{b[0][:8]}\t{b[1]}\t{a_[0][:8]}\t{a_[1]}\t{len([c for c in caps if '2017' <= c[:4] <= '2018'])}\n")
    out.flush()
