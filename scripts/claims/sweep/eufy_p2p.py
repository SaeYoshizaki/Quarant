#!/usr/bin/env python3
"""What the Eufy HomeBase sends in its P2P (PPPP) stream: splits the DRW packets it sends into XZYH messages and
reports, per capture, how many video and audio frames there are, which ones start in the clear, and how many bytes
could be encrypted. Optionally writes the AAC audio (ADTS) as it was sent. Nothing is decrypted.

usage: eufy_p2p.py [--audio-dir DIR] <pcap> [pcap...]

Layout (as read from the packets; eufy-security-client src/p2p/session.ts parses the same fields):
  PPPP:  f1 d0 <len:2 BE> d1 <channel:1> <index:2 BE> <data>        (channel 1 carries video and audio)
  XZYH:  "XZYH" <cmd:2 LE> <len:4 LE> .. <sign:1 at offset 13> .. <body>   (16-byte header)
  video (cmd 1300): <data_len:4 LE> <key:1> <codec:1> <seq:2> <fps:2> <w:2> <h:2> <ts:6> <2> [128-byte key + 1 if sign]
  audio (cmd 1301): 16-byte header, then ADTS AAC
"""
import argparse
import collections
import struct
import subprocess
import sys
from pathlib import Path

HOMEBASE = "8c:85:80:6c:b6:47"
HEVC_TRAIL_R = bytes.fromhex("000000010201")


def drw(pcap):
    """channel -> {index: (frame, data)} for DRW packets the HomeBase sent (first copy of each index)."""
    out = subprocess.run(
        ["tshark", "-r", pcap, "-Y", f"eth.src=={HOMEBASE} && udp && !dns", "-T", "fields",
         "-e", "frame.number", "-e", "ip.dst", "-e", "udp.dstport", "-e", "data.data"],
        capture_output=True, text=True, check=True).stdout
    chans = collections.defaultdict(dict)
    dests = collections.Counter()
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 4 or not p[3]:
            continue
        b = bytes.fromhex(p[3])
        if len(b) < 8 or b[0] != 0xF1 or b[1] != 0xD0 or b[4] != 0xD1:
            continue
        dests[(p[1], p[2])] += 1
        chans[b[5]].setdefault(struct.unpack(">H", b[6:8])[0], (int(p[0]), b[8:]))
    return chans, dests


def messages(chunks):
    """Yields (first frame, cmd, header, body). Drops data up to the next XZYH after a lost packet."""
    buf, start = b"", None
    for frame, data in chunks:
        if not buf:
            start = frame
        buf += data
        while len(buf) >= 16 and buf[:4] == b"XZYH":
            cmd, n = struct.unpack("<HI", buf[4:10])
            if len(buf) < 16 + n:
                break
            yield start, cmd, buf[:16], buf[16:16 + n]
            buf, start = buf[16 + n:], frame
        if len(buf) >= 4 and buf[:4] != b"XZYH":
            k = buf.find(b"XZYH")
            buf = buf[k:] if k >= 0 else b""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--audio-dir")
    ap.add_argument("pcap", nargs="+")
    a = ap.parse_args()
    for pcap in a.pcap:
        chans, dests = drw(pcap)
        if 1 not in chans:
            print(f"{Path(pcap).name}: no stream")
            continue
        c, first, audio = collections.Counter(), {}, b""
        for frame, cmd, hdr, body in messages(chans[1][i] for i in sorted(chans[1])):
            if cmd == 1300:
                n = struct.unpack("<I", body[0:4])[0]
                signed = hdr[13] > 0 and n >= 128
                payload = body[151 if signed else 22:]
                k = "video_signed" if signed else "video_other"
                c[k] += 1
                c["video_bytes"] += len(payload)
                first.setdefault(k, frame)
                if signed:
                    c["encrypted_at_most"] += 128
                    w, h = struct.unpack("<HH", body[10:14])
                    c[f"{w}x{h}"] += 1
                else:
                    c["video_other_hevc_start"] += payload[:6] == HEVC_TRAIL_R
            elif cmd == 1301:
                c["audio"] += 1
                c["audio_adts"] += body[16:18] in (b"\xff\xf1", b"\xff\xf9")
                first.setdefault("audio", frame)
                audio += body[16:]
        dest = ", ".join(f"{ip}:{port} ({n})" for (ip, port), n in dests.most_common(2))
        share = c["encrypted_at_most"] / c["video_bytes"] if c["video_bytes"] else 0
        print(f"{Path(pcap).name}: to {dest}; {dict(c)}; first frames {first}; encrypted at most {share:.2%} of video")
        if a.audio_dir and audio:
            Path(a.audio_dir, Path(pcap).stem + ".aac").write_bytes(audio)


if __name__ == "__main__":
    sys.exit(main())
