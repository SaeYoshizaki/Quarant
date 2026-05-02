# Quarant

IoT network traffic analyzer for passive security monitoring.

Quarant observes IoT device traffic on a Linux gateway / bridge / router and records network-visible risk signals related to the OWASP IoT Top 10.

![Quarant dashboard placeholder](docs/images/dashboard-placeholder.png)

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Getting Started](#getting-started)
- [Short CLI](#short-cli)
- [Report Viewer](#report-viewer)
- [Documentation](#documentation)
- [Build Process](#build-process)

## Introduction

Quarant is a passive monitoring tool for IoT networks.
It captures packets, reconstructs TCP flows, parses protocol metadata, and writes detected events to `events.jsonl`.

It focuses on what can be observed from network traffic:

- insecure services
- plaintext communication
- exposed credentials or tokens
- update-like traffic
- unexpected destinations
- device inventory and per-device risk summary

Quarant is not a firmware emulator or an active vulnerability scanner.
It does not log in to devices, exploit them, or decrypt HTTPS traffic.

## Features

- Capture packets from a Linux network interface
- Read packets from a `.pcap` file
- Read a streamed `pcap` from standard input
- Reconstruct TCP flows for protocol-level analysis
- Parse HTTP, TLS, MQTT, and Telnet traffic
- Detect plaintext credentials, cookies, tokens, and API keys
- Observe TLS metadata such as SNI, TLS version, cipher suite, and JA3
- Detect insecure services such as Telnet, FTP, RTSP, MQTT, CoAP, and HTTP management interfaces
- Export events as `events.jsonl`
- Export flow summaries as `flows.jsonl`
- Export device inventory as `device_inventory.json`
- Show events in the existing Web report viewer
- Map network-visible signals to OWASP IoT Top 10 categories

## Getting Started

### Requirements

- Linux environment
- Go 1.24 or later
- libpcap development package
- root privilege or packet capture capability
- Node.js and npm when building the Web viewer

Ubuntu / Debian:

```bash
sudo apt update
sudo apt install -y git build-essential libpcap-dev
```

### Install

```bash
git clone https://github.com/SaeYoshizaki/Quarant.git
cd Quarant
go mod download
```

### Build

```bash
go build -o quarant ./cmd/quarant
go build ./cmd/quarant-api
```

## Short CLI

### Analyze a pcap file

```bash
./quarant analyze sample.pcap --out events.jsonl
```

This also writes `flows.jsonl` by default.
`quarant analyze` replaces existing `events.jsonl` and `flows.jsonl` unless you pass `--append`.

### Analyze a streamed pcap from standard input

```bash
ssh root@192.168.1.1 "tcpdump -i br-lan -U -s 0 -w - 'host 192.168.1.144'" \
  | ./quarant analyze - --out events.jsonl
```

Append instead of replacing:

```bash
./quarant analyze sample.pcap --out events.jsonl --append
```

### Launch the local report viewer from `events.jsonl`

```bash
./quarant report events.jsonl --open
```

### Launch the local report viewer from `report.json`

```bash
./quarant report report.json --open
```

### Analyze and then open the report viewer

```bash
./quarant analyze sample.pcap --out events.jsonl --report --open
```

## Report Viewer

Quarant reuses the existing `web/` UI. It does not generate a second UI.

### One-time Web build

Before using `quarant report` or `quarant-api -open`, build the exported Web viewer once:

```bash
cd web
NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8080 npm run build
cd ..
```

This creates `web/out`, which `quarant report` and `quarant-api` serve on the same localhost port as the API.

### Local viewer from the short CLI

```bash
./quarant report report.json --open
```

### Local viewer from the development CLI

```bash
go run ./cmd/quarant-api -report-in report.json -open
```

### Existing two-process development flow

If you prefer the Next.js dev server during UI development, keep using the existing split flow:

```bash
go run ./cmd/quarant-api -report-in report.json -addr 127.0.0.1:8080
cd web
NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8080 npm run dev
```

Then open:

```text
http://127.0.0.1:3000
```

## Legacy CLI

The previous interface-driven entrypoint still works:

```bash
sudo ./quarant -i eth0
./quarant -pcap capture.pcap
./quarant -pcap -
```

## Documentation

- [`docs/demo.md`](docs/demo.md) - Ubuntu / Linux / containerlab demo and test scenarios
- [`docs/design.md`](docs/design.md) - architecture, design policy, OWASP IoT Top 10 mapping, and passive monitoring limitations
- `examples/` - example `events.jsonl` and `device_inventory.json`

## Build Process

### Test

```bash
go test ./...
```

### Smoke test

```bash
./quarant analyze sample.pcap --out events.jsonl
./quarant report events.jsonl
```
