# Docker OpenWrt-Compatible Lab

この lab は、実機 OpenWrt の前段階として使う Quarant の再現可能な評価環境です。

目的は OpenWrt 本体を完全に仮想化することではなく、OpenWrt fw4 / nftables 境界ログに近い raw evidence を Docker 上で安定生成し、Quarant の importer / experiment / report pipeline を繰り返し検証することです。

## 生成する evidence

`docker compose up` で以下を生成します。

```text
out/before/openwrt/raw/firewall.log
out/before/openwrt/raw/dnsmasq.log
out/before/openwrt/raw/dhcp.leases
out/before/openwrt/raw/conntrack.txt
out/after/openwrt/raw/firewall.log
out/after/openwrt/raw/dnsmasq.log
out/after/openwrt/raw/dhcp.leases
out/after/openwrt/raw/conntrack.txt
```

before window は WAN から IoT camera への ACCEPT / exposed service attempt を含みます。after window は同じ scan volume を残しつつ、ACCEPT/exposed を DROP/REJECT に寄せます。これにより「インターネット上の scan 数が減った」ではなく、「gateway が制御できる exposed/accepted evidence が減った」ことを評価できます。

## 実行

```bash
cd evaluation/docker-openwrt-lab
docker compose up --abort-on-container-exit
```

生成後、リポジトリ root から Quarant pipeline を実行します。

```bash
go run ./cmd/quarant experiment run \
  --before-openwrt evaluation/docker-openwrt-lab/out/before/openwrt/raw \
  --after-openwrt evaluation/docker-openwrt-lab/out/after/openwrt/raw \
  --before-now 2026-09-26T12:30:00Z \
  --after-now 2026-09-26T13:30:00Z \
  --out runs/docker-openwrt-lab
```

## 位置づけ

- CI / regression: この lab と `examples/integrated` を golden fixture として使う。
- lab-generated dataset: Docker で制御した before/after を増やす。
- real OpenWrt: 最後に実機の `logread` / fw4 rule / interface 名の揺れを確認する。

実機評価の代替ではありません。論文や report では、Docker lab は controlled evidence generation、実機 OpenWrt は deployment reality check と分けて扱います。
