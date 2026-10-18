#!/usr/bin/env python3
"""Concatenate pcap files (same link type) into one pcap stream on stdout,
in the order given. Used for captures split into short files, such as
YourThings (one file per 5 minutes), so that connections and device state
are not cut at file boundaries.

usage: pcapcat.py FILE... > merged.pcap
"""
import struct
import sys


def main():
    out = sys.stdout.buffer
    header = None
    for path in sys.argv[1:]:
        with open(path, "rb") as f:
            h = f.read(24)
            if len(h) < 24:
                continue
            if header is None:
                header = h
                out.write(h)
            elif h[:4] != header[:4] or h[20:24] != header[20:24]:
                sys.exit(f"{path}: different byte order or link type")
            e = "<" if h[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
            while True:
                rec = f.read(16)
                if len(rec) < 16:
                    break
                incl = struct.unpack(e + "I", rec[8:12])[0]
                data = f.read(incl)
                if len(data) < incl:
                    break  # truncated last record
                out.write(rec)
                out.write(data)


if __name__ == "__main__":
    main()
