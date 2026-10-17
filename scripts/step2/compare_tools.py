#!/usr/bin/env python3
"""Step 2 (RQ3): compare Quarant with Zeek and Suricata on the same captures.

Each run directory holds the three tools' output for one capture:
  <run>/quarant/{events.jsonl,device_inventory.json}
  <run>/zeek/{notice.log,ssl.log,http.log,software.log,...}   (JSON logs)
  <run>/suricata/eve.json

Two comparisons, both under one rule for every tool:
  A. Detection of labelled conditions (UNSW attack windows, IoT-23 malicious
     flow classes) and alerts on benign traffic. "Alert" means a Quarant
     event of severity WARNING or above, a Suricata alert from an ET
     signature (engine events "SURICATA ..." are counted separately), or a
     Zeek notice (CaptureLoss::* excluded). A window counts as detected when
     an alert involving the victim's IP falls in [start-slack, end+slack];
     the same test on the window shifted one hour earlier gives the chance
     rate of that lenient criterion.
  B. Evidence for the ETSI EN 303 645 provisions Quarant reports (E4/E5):
     per IoT device, whether each tool's alerts, or its logs, carry the fact.

Devices are identified by MAC via Quarant's inventory for all tools, and the
non-IoT MACs in docs/assessment/non-iot-macs.txt are excluded.

usage: compare_tools.py OUT_DIR UNSW_ANNOTATIONS_DIR IOT23_DIR NON_IOT_MACS REPORT_MD [SUMMARY_JSON]
"""
import collections
import datetime as dt
import glob
import ipaddress
import json
import os
import re
import sys

SLACK = 120.0
SHIFT = 3600.0
WEAK_TLS_ZEEK = {"SSLv2", "SSLv3", "TLSv10", "TLSv11"}
WEAK_TLS_SURICATA = {"SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLSv1"}
SURICATA_BASIC_AUTH = re.compile(r"Basic Auth|Password detected unencrypted|Cleartext|Plaintext", re.I)
SURICATA_UPNP = re.compile(r"UPnP|AddPortMapping", re.I)
VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)?")
# Attack/behaviour-class alerts, used for A1/A2. Posture findings (cleartext,
# TLS, certificates, privacy) and informational signatures are not attacks.
QUARANT_ATTACK = {"PERSISTENT_CONNECTION_ATTEMPTS", "PERIODIC_COMMUNICATION_OBSERVED", "IP_MAC_BINDING_CHANGED"}
SURICATA_INFO = ("ET INFO", "ET POLICY", "ET CHAT", "GPL CHAT", "ET P2P", "ET DNS", "ET DYN_DNS", "ET FILE_SHARING",
                 "ET GAMES", "GPL POLICY", "GPL INFO", "ET TOR", "GPL P2P")
ZEEK_POSTURE = ("SSL::", "Software::", "CaptureLoss::", "Notice::")


def attack_class(tool, name):
    if tool == "quarant":
        return name in QUARANT_ATTACK or name.endswith("_SCAN_SUSPECTED")
    if tool == "suricata":
        return not name.startswith(SURICATA_INFO)
    return not name.startswith(ZEEK_POSTURE)


GROUPS = [("unsw-", "UNSW 2016 (benign)"), ("unswatk-", "UNSW 2018 (attacks)"), ("iot23-", "IoT-23 2018-19")]
TOOLS = ["quarant", "suricata", "zeek"]


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def iso_ts(s):
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return None


def jsonl(path):
    if not os.path.exists(path):
        return
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


class Run:
    """All three tools' output for one capture, normalised."""

    def __init__(self, d):
        self.name = os.path.basename(d)
        self.dir = d
        self.alerts_all = {t: [] for t in TOOLS}   # (ts, src, dst, name)
        self.alerts = {t: [] for t in TOOLS}       # attack/behaviour class only
        self.engine_events = 0                # Suricata decoder/stream events
        self.ip_mac = {}
        self.mac_ips = collections.defaultdict(set)
        self.devices = set()                  # IPs with observed traffic
        self.inventory = {}
        self.start = self.end = None
        self._load()

    def _load(self):
        inv = os.path.join(self.dir, "quarant", "device_inventory.json")
        if os.path.exists(inv):
            for d in json.load(open(inv)).get("devices") or []:
                ip, mac = d.get("ip"), (d.get("mac_address") or "").lower()
                self.inventory[ip] = d
                if mac:
                    self.ip_mac[ip] = mac
                    self.mac_ips[mac].add(ip)
                if d.get("observed_protocols"):
                    self.devices.add(ip)
                for k in ("first_seen", "last_seen"):
                    t = iso_ts(d.get(k) or "")
                    if t is not None:
                        self.start = t if self.start is None else min(self.start, t)
                        self.end = t if self.end is None else max(self.end, t)
        self.quarant_events = []
        for e in jsonl(os.path.join(self.dir, "quarant", "events.jsonl")):
            if e.get("debug"):
                continue
            e["_ts"] = iso_ts(e.get("ts", ""))
            self.quarant_events.append(e)
            if e.get("severity", "").upper() in ("WARNING", "HIGH", "CRITICAL", "MEDIUM"):
                self.alerts["quarant"].append((e["_ts"], e.get("src_ip", ""), e.get("dst_ip", ""), e["type"]))
        self.eve = []
        for e in jsonl(os.path.join(self.dir, "suricata", "eve.json")):
            et = e.get("event_type")
            if et == "alert":
                sig = e["alert"].get("signature", "")
                if sig.startswith("SURICATA "):
                    self.engine_events += 1
                    continue
                self.alerts["suricata"].append((iso_ts(e["timestamp"]), e.get("src_ip", ""), e.get("dest_ip", ""), sig))
            elif et in ("tls", "http"):
                self.eve.append(e)
        for n in jsonl(os.path.join(self.dir, "zeek", "notice.log")):
            note = n.get("note", "")
            if note.startswith("CaptureLoss::"):
                continue
            src = n.get("id.orig_h") or n.get("src") or ""
            dst = n.get("id.resp_h") or n.get("dst") or ""
            self.alerts["zeek"].append((n.get("ts"), src, dst, note))
        for t in TOOLS:
            self.alerts_all[t] = self.alerts[t]
            self.alerts[t] = [a for a in self.alerts_all[t] if attack_class(t, a[3])]

    def zeek(self, log):
        return jsonl(os.path.join(self.dir, "zeek", log))

    def device_mac(self, ip):
        return self.ip_mac.get(ip, ip)


def involves(alert, ips):
    return alert[1] in ips or alert[2] in ips


def any_alert(alerts, ips, lo, hi):
    return [a for a in alerts if a[0] is not None and lo <= a[0] <= hi and (ips is None or involves(a, ips))]


# ---------------------------------------------------------------- A. UNSW attacks

def load_windows(annot_dir):
    out = []
    for path in glob.glob(os.path.join(annot_dir, "*.csv")):
        raw = os.path.basename(path)[:-4].lower()
        mac = ":".join(raw[i:i + 2] for i in range(0, 12, 2)) if len(raw) == 12 else raw
        for line in open(path):
            cols = line.strip().split(",")
            if len(cols) < 4:
                continue
            try:
                s, e = float(cols[0]), float(cols[1])
            except ValueError:
                continue
            attack = cols[-1].strip()
            fam = re.match(r"^([A-Za-z]+?)(\d+)", attack)
            out.append({"mac": mac, "start": s, "end": e, "attack": attack, "family": fam.group(1) if fam else attack})
    return out


def eval_unsw_attacks(runs, windows):
    fam = collections.defaultdict(lambda: {"windows": 0, **{t: [0, 0] for t in TOOLS}, **{t + "_any": [0, 0] for t in TOOLS},
                                           "names": {t: collections.Counter() for t in TOOLS}})
    by_victim = collections.defaultdict(list)
    for w in windows:
        by_victim[w["mac"]].append(w)
    for r in runs:
        if r.start is None:
            continue
        for w in windows:
            if w["start"] < r.start or w["end"] > r.end:
                continue
            ips = r.mac_ips.get(w["mac"], set())
            f = fam[w["family"]]
            f["windows"] += 1
            lo, hi = w["start"] - SLACK, w["end"] + SLACK
            # chance window: one hour earlier, inside the capture, not overlapping
            # another attack on the same victim
            clo, chi = lo - SHIFT, hi - SHIFT
            chance_ok = clo >= r.start and not any(o["start"] - SLACK <= chi and clo <= o["end"] + SLACK for o in by_victim[w["mac"]])
            for t in TOOLS:
                hits = any_alert(r.alerts[t], ips, lo, hi) if ips else []
                f[t][0] += 1 if hits else 0
                for h in hits:
                    f["names"][t][h[3]] += 1
                hits_any = any_alert(r.alerts[t], None, lo, hi)
                f[t + "_any"][0] += 1 if hits_any else 0
                if chance_ok:
                    f[t][1] += 1 if (ips and any_alert(r.alerts[t], ips, clo, chi)) else 0
                    f[t + "_any"][1] += 1 if any_alert(r.alerts[t], None, clo, chi) else 0
            f.setdefault("chance_windows", 0)
            f["chance_windows"] += 1 if chance_ok else 0
    return fam


# ---------------------------------------------------------------- A. IoT-23

def parse_iot23_labels(path):
    flows, fields = [], None
    for line in open(path, errors="replace"):
        if line.startswith("#fields"):
            fields = []
            for name in line.rstrip("\n").split("\t")[1:]:
                fields += name.split()
            continue
        if line.startswith("#") or fields is None:
            continue
        cols = line.rstrip("\n").split("\t")
        if len(cols) < len(fields):
            cols = cols[:-1] + cols[-1].split()
        row = dict(zip(fields, cols))
        flows.append(row)
    return flows


def eval_iot23(runs, iot23_dir):
    out = []
    for r in runs:
        scen = r.name[len("iot23-"):]
        lp = os.path.join(iot23_dir, scen, "conn.log.labeled")
        if not os.path.exists(lp):
            continue
        flows = parse_iot23_labels(lp)
        count = collections.Counter(f.get("id.orig_h") for f in flows)
        host = count.most_common(1)[0][0] if count else ""
        classes = collections.defaultdict(set)
        for f in flows:
            if f.get("id.orig_h") == host and f.get("label", "").lower() == "malicious":
                det = f.get("detailed-label") or f.get("detailed_label") or "-"
                classes[det if det != "-" else "Malicious(unspecified)"].add(f.get("id.resp_h"))
        mal_dsts = set().union(*classes.values()) if classes else set()
        res = {"scenario": scen, "host": host, "classes": {}, "alerts_on_host": {}, "alerts_outside_malicious": {}}
        for t in TOOLS:
            on_host = [a for a in r.alerts[t] if involves(a, {host})]
            res.setdefault("all_alerts_on_host", {})[t] = sum(1 for a in r.alerts_all[t] if involves(a, {host}))
            # notices that name only the host (e.g. Zeek SSH::Password_Guessing
            # has no responder) cannot be tied to one class
            res.setdefault("host_only", {})[t] = collections.Counter(
                a[3] for a in on_host if not (a[2] if a[1] == host else a[1])).most_common(3)
            res["alerts_on_host"][t] = len(on_host)
            res["alerts_outside_malicious"][t] = sum(1 for a in on_host if (a[2] if a[1] == host else a[1]) not in mal_dsts)
        for c, dsts in sorted(classes.items()):
            res["classes"][c] = {"destinations": len(dsts)}
            for t in TOOLS:
                hits = [a for a in r.alerts[t] if (a[1] == host and a[2] in dsts) or (a[2] == host and a[1] in dsts)]
                res["classes"][c][t] = collections.Counter(h[3] for h in hits).most_common(3)
        out.append(res)
    return out


# ---------------------------------------------------------------- A. benign alerts

def eval_benign(runs, exclude):
    out = []
    for r in runs:
        res = {"run": r.name, "engine_events": r.engine_events}
        for t in TOOLS:
            def on_iot(alerts):
                return [a for a in alerts if any(ip in r.devices and r.device_mac(ip) not in exclude for ip in (a[1], a[2]))]
            iot, iot_all = on_iot(r.alerts[t]), on_iot(r.alerts_all[t])
            devs = {r.device_mac(ip) for a in iot for ip in (a[1], a[2]) if ip in r.devices and r.device_mac(ip) not in exclude}
            res[t] = {"alerts": len(iot), "devices": len(devs), "all_alerts": len(iot_all),
                      "top": collections.Counter(a[3] for a in iot).most_common(5),
                      "top_all": collections.Counter(a[3] for a in iot_all).most_common(3)}
        out.append(res)
    return out


# ---------------------------------------------------------------- B. evidence

def quarant_matches(e, types, require=None, exclude=None, external=False):
    if e["type"] not in types:
        return False
    ev = e.get("evidence") or ""
    if require and not re.search(require, ev):
        return False
    if exclude and re.search(exclude, ev):
        return False
    if external and (not e.get("dst_ip") or is_private(e.get("dst_ip"))):
        return False
    return True


def eval_evidence(runs, exclude):
    """per group -> provision -> tool -> set(device MACs)"""
    res = collections.defaultdict(lambda: collections.defaultdict(lambda: collections.defaultdict(set)))
    seen = collections.defaultdict(set)
    for r in runs:
        group = next((g for p, g in GROUPS if r.name.startswith(p)), None)
        if group is None:
            continue
        iot = {ip for ip in r.devices if r.device_mac(ip) not in exclude}
        seen[group] |= {r.device_mac(ip) for ip in iot}

        def add(prov, tool, ip):
            if ip in iot:
                res[group][prov][tool].add(r.device_mac(ip))

        for e in r.quarant_events:
            dev = e.get("device_key") or e.get("src_ip", "")
            if quarant_matches(e, {"I7_TLS_WEAK_VERSION_OBSERVED"}, "risk_kind=deprecated_tls_version"):
                add("5.5-1 deprecated TLS", "quarant", dev)
            if quarant_matches(e, {"INSECURE_HTTP_AUTH"}, "Authorization: Basic"):
                add("5.5-6 HTTP Basic credentials", "quarant", dev)
            if quarant_matches(e, {"INSECURE_HTTP_AUTH", "INSECURE_HTTP_COOKIE", "INSECURE_HTTP_TOKEN", "INSECURE_MQTT_CREDENTIALS",
                                   "INSECURE_TELNET_CREDENTIALS", "I3_AUTH_TOKEN_IN_URL"}, exclude=r"^(serial|device_id)="):
                add("5.5-6 any CSP in cleartext", "quarant", dev)
            if quarant_matches(e, {"I6_HTTP_PRIVACY_EXPOSURE", "I6_HTTP_UNEXPECTED_PII", "I6_PII_TO_UNEXPECTED_DESTINATION"}):
                add("5.8-1 personal data in cleartext", "quarant", dev)
            if quarant_matches(e, {"I9_UPNP_PORT_MAPPING_REQUESTED"}):
                add("5.12-1 UPnP port mapping", "quarant", dev)
            if quarant_matches(e, {"I3_UNAUTHENTICATED_DEVICE_CONTROL"},
                               exclude=r"/(MediaRenderer|MediaServer)/|soap_action=(GetProtocolInfo|Browse|Search|GetCurrentConnectionInfo|GetTransportInfo|GetPositionInfo|GetVolume|GetMute)\b"):
                add("5.5-4 unauthenticated control", "quarant", dev)
        for ip, d in r.inventory.items():
            for ev in d.get("identity_evidence") or []:
                if ev.get("attribute") in ("ssdp_server", "mdns_txt") and VERSION_RE.search(ev.get("value", "")):
                    add("5.6-2 version disclosed (candidate)", "quarant", ip)
        for a in r.alerts_all["suricata"]:
            if SURICATA_BASIC_AUTH.search(a[3]):
                add("5.5-6 HTTP Basic credentials", "suricata", a[1])
                add("5.5-6 any CSP in cleartext", "suricata", a[1])
            if SURICATA_UPNP.search(a[3]):
                add("5.12-1 UPnP port mapping", "suricata (any UPnP signature)", a[1])
                add("5.12-1 UPnP port mapping", "suricata (any UPnP signature)", a[2])
        for e in r.eve:
            if e["event_type"] == "tls" and (e.get("tls") or {}).get("version") in WEAK_TLS_SURICATA:
                add("5.5-1 deprecated TLS", "suricata log", e.get("src_ip"))
        for s in r.zeek("ssl.log"):
            if s.get("version") in WEAK_TLS_ZEEK:
                add("5.5-1 deprecated TLS", "zeek log", s.get("id.orig_h"))
        for h in r.zeek("http.log"):
            if h.get("username") not in (None, "", "-"):
                add("5.5-6 HTTP Basic credentials", "zeek log", h.get("id.orig_h"))
                add("5.5-6 any CSP in cleartext", "zeek log", h.get("id.orig_h"))
        for s in r.zeek("software.log"):
            if s.get("version.major") is not None:
                add("5.6-2 version disclosed (candidate)", "zeek log", s.get("host"))
        for a in r.alerts_all["zeek"]:
            if a[3].startswith("SSL::"):
                add("(zeek notice) " + a[3], "zeek", a[1])
    return res, seen


# ---------------------------------------------------------------- report

def pct(n, d):
    return f"{n}/{d}" + (f" ({100 * n / d:.0f}%)" if d else "")


def main():
    out_dir, annot, iot23_dir, nonio, report = sys.argv[1:6]
    summary_path = sys.argv[6] if len(sys.argv) > 6 else None
    exclude = {l.strip().lower() for l in open(nonio) if l.strip() and not l.startswith("#")}
    runs = [Run(d) for d in sorted(glob.glob(os.path.join(out_dir, "*"))) if os.path.isdir(os.path.join(d, "quarant"))]
    L = ["# Step 2: Quarant, Zeek and Suricata on the same captures", "",
         "Generated by `scripts/step2/compare_tools.py`. Alert = Quarant WARNING+ event, Suricata ET signature alert, "
         "Zeek notice (CaptureLoss excluded). Suricata engine events (`SURICATA ...`) are reported separately.",
         "A1/A2 use attack/behaviour-class alerts only: Quarant scan/persistent/periodic/binding-change findings, "
         "Suricata signatures outside INFO/POLICY/CHAT/P2P/DNS/DYN_DNS/FILE_SHARING/GAMES/TOR, Zeek notices outside SSL::/Software::.", ""]

    atk = eval_unsw_attacks([r for r in runs if r.name.startswith("unswatk-")], load_windows(annot))
    L += ["## A1. UNSW 2018 attack windows", "",
          f"Detected = an alert involving the victim's IP within the window ±{SLACK:.0f} s. "
          "Chance = the same test on the window shifted one hour earlier (where that window is free of attacks on the victim).", "",
          "| Attack family | Windows | Quarant | (chance) | Suricata | (chance) | Zeek | (chance) |", "|---|---|---|---|---|---|---|---|"]
    tot = {t: [0, 0] for t in TOOLS}
    totw = totc = 0
    for name in sorted(atk):
        f = atk[name]
        cw = f.get("chance_windows", 0)
        row = [name, str(f["windows"])]
        for t in TOOLS:
            row += [pct(f[t][0], f["windows"]), pct(f[t][1], cw)]
            tot[t][0] += f[t][0]
            tot[t][1] += f[t][1]
        totw += f["windows"]
        totc += cw
        L.append("| " + " | ".join(row) + " |")
    L.append("| **all** | " + str(totw) + " | " + " | ".join(pct(tot[t][0], totw) + " | " + pct(tot[t][1], totc) for t in TOOLS) + " |")
    L += ["", "Alert names that matched attack windows (top 3 per family and tool):", ""]
    for name in sorted(atk):
        parts = []
        for t in TOOLS:
            top = ", ".join(f"{k} ({v})" for k, v in atk[name]["names"][t].most_common(3)) or "—"
            parts.append(f"{t}: {top}")
        L.append(f"- **{name}**: " + "; ".join(parts))

    io = eval_iot23([r for r in runs if r.name.startswith("iot23-")], iot23_dir)
    L += ["", "## A2. IoT-23 malicious flow classes", "",
          "Detected = an alert between the infected host and a destination of that class. Cells list the top alert names.", "",
          "| Scenario | Class (destinations) | Quarant | Suricata | Zeek |", "|---|---|---|---|---|"]
    for s in io:
        for c, v in s["classes"].items():
            cells = ["; ".join(f"{k} ({n})" for k, n in v[t]) or "—" for t in TOOLS]
            L.append(f"| {s['scenario']} | {c} ({v['destinations']}) | " + " | ".join(cells) + " |")
    L += ["", "| Scenario | Attack-class alerts on host (Q / S / Z) | of which outside malicious destinations | All alerts on host | Alerts naming only the host |", "|---|---|---|---|---|"]
    for s in io:
        only = "; ".join(f"{t}: " + ", ".join(f"{k} ({n})" for k, n in s["host_only"][t]) for t in TOOLS if s["host_only"][t]) or "—"
        L.append(f"| {s['scenario']} | " + " / ".join(str(s["alerts_on_host"][t]) for t in TOOLS) + " | " +
                 " / ".join(str(s["alerts_outside_malicious"][t]) for t in TOOLS) + " | " +
                 " / ".join(str(s["all_alerts_on_host"][t]) for t in TOOLS) + f" | {only} |")

    ben = eval_benign([r for r in runs if r.name.startswith("unsw-")], exclude)
    L += ["", "## A3. Alerts on benign traffic (UNSW 2016, IoT devices only)", "",
          "Attack/behaviour-class alerts (devices); in brackets all alerts including posture and informational ones.", "",
          "| Day | Quarant | Suricata | Zeek | Suricata engine events |", "|---|---|---|---|---|"]
    for b in ben:
        L.append(f"| {b['run']} | " + " | ".join(f"{b[t]['alerts']} ({b[t]['devices']} dev) [{b[t]['all_alerts']}]" for t in TOOLS) + f" | {b['engine_events']} |")
    L += [""]
    for b in ben:
        for t in TOOLS:
            L.append(f"- {b['run']} {t}: attack-class " + (", ".join(f"{k} ({v})" for k, v in b[t]["top"]) or "—") +
                     "; all: " + (", ".join(f"{k} ({v})" for k, v in b[t]["top_all"]) or "—"))

    ev, seen = eval_evidence(runs, exclude)
    L += ["", "## B. Evidence for ETSI EN 303 645 provisions (IoT devices with the evidence)", "",
          "`quarant` = Quarant event (interpreted, with basis and limitation); `suricata` / `zeek` = alert or notice; "
          "`... log` = the fact appears in the tool's protocol log but no alert is raised.", ""]
    for _, g in GROUPS:
        if g not in seen:
            continue
        L += [f"### {g} ({len(seen[g])} IoT devices)", "", "| Provision / evidence | Source | Devices |", "|---|---|---|"]
        for prov in sorted(ev[g]):
            for tool in sorted(ev[g][prov]):
                L.append(f"| {prov} | {tool} | {len(ev[g][prov][tool])} |")
        L.append("")
    open(report, "w").write("\n".join(L) + "\n")
    print("\n".join(L))
    if summary_path:
        json.dump({"attacks": {k: {kk: vv for kk, vv in v.items() if kk != "names"} for k, v in atk.items()},
                   "iot23": io, "benign": ben,
                   "evidence": {g: {p: {t: sorted(s) for t, s in v.items()} for p, v in pv.items()} for g, pv in ev.items()}},
                  open(summary_path, "w"), indent=1, default=list)


if __name__ == "__main__":
    main()
