#!/bin/bash
# Analyse one day of a capture split into short files (YourThings: one file
# per 5 minutes) as a single stream, in time order: Quarant, and the
# ground truth of scripts/accuracy (Zeek gt.zeek, rawscan.py).
# usage: run_split_day.sh QUARANT_BIN DAY_DIR NAME RUNS_OUT GT_OUT
set -euo pipefail
Q=$1; DAY=$2; NAME=$3; RUNS=$4; GT=$5
here=$(cd "$(dirname "$0")" && pwd)
# file names end in the epoch of their first packet: sort on it
files=$(ls "$DAY" | grep -v '^\._' | sort -t. -k3,3n | sed "s|^|$DAY/|")
mkdir -p "$RUNS/$NAME" "$GT/$NAME"
cat_day() { python3 -I "$here/pcapcat.py" $files; }
( cat_day | "$Q" analyze - --out "$RUNS/$NAME/events.jsonl" > "$RUNS/$NAME/quarant.log" 2>&1
  rm -f "$RUNS/$NAME/observations.jsonl" "$RUNS/$NAME/flows.jsonl" ) &
if command -v zeek >/dev/null; then
  ( cd "$GT/$NAME" && cat_day | zeek -C -r - "$here/gt.zeek" LogAscii::use_json=T > zeek.stderr 2>&1
    ls *.log | grep -v '^gt.log$' | xargs rm -f ) &
else
  echo "zeek not installed: no gt.log" > "$GT/$NAME/zeek.stderr"
fi
( cat_day | python3 -I "$here/rawscan.py" /dev/stdin "$GT/$NAME/raw.jsonl" 2> "$GT/$NAME/raw.stderr" ) &
wait
echo "$(echo "$files" | wc -l | tr -d ' ') files" > "$GT/$NAME/done"
echo "$NAME done"
