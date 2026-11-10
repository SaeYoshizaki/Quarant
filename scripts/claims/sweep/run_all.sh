#!/bin/bash
# Run expose.py over the five datasets kept on the external disk, one dataset after another.
# CIC IoT 2022: the 6-Attacks captures are left out (devices under attack).
# usage: run_all.sh [dataset...]   (default: all five)
set -u
cd "$(dirname "$0")/../../.."
R=~/datasets/raw
OUT=~/datasets/claims/sweep
# the external disk is the bottleneck; more readers at once make it seek
export SWEEP_PROCS=${SWEEP_PROCS:-3}
sources() {
  case $1 in
    yourthings) ls /Volumes/QuarantData/usb-yourthings/iot_traffic2018*.tgz ;;
    unsw2016) ls $R/unsw-iot-traces/*.tar.gz ;;
    iotraffic) echo $R/unsw-iotraffic/pcaps ;;
    cic2022) echo $R/cic-iot-2022/1-Power $R/cic-iot-2022/2-Idle $R/cic-iot-2022/3-Interactions $R/cic-iot-2022/4-Scenarios $R/cic-iot-2022/2021_11_02_Active.pcap ;;
    deakin) echo $R/deakin-iot/pcapFull ;;
  esac
}
for ds in ${@:-yourthings cic2022 deakin iotraffic unsw2016}; do
  mkdir -p $OUT/$ds
  python3 scripts/claims/sweep/expose.py docs/claims/devices.tsv $ds $OUT/$ds $(sources $ds) >> $OUT/$ds.log 2>&1
  echo "$(date +%H:%M:%S) $ds done" >> $OUT/run_all.log
done
