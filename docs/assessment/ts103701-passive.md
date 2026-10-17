# ETSI TS 103 701 試験ケースのパッシブ評価可能性

自動生成（`scripts/assessment/consolidate.py`）。分類基準は [RUBRIC.md](RUBRIC.md)。規格の本文はリポジトリに含めず、条項番号と要約（言い換え）だけを置く。

- 試験グループ（要件）: 78、試験ケース: 131

## 要件（試験グループ）単位

| 区分 | 件数 |
|---|---|
| 観測（observed） | 0 |
| 推定（inferred） | 26 |
| 照合（reference） | 0 |
| 判定不能（not_assessable） | 52 |

| 判定の向き | 要件数 | 試験ケース数 |
|---|---|---|
| 合否とも（pass_and_fail） | 3 | 3 |
| 不合格のみ（fail_only） | 21 | 27 |
| 合格のみ（pass_only） | 2 | 3 |
| 判定できない（none） | 52 | 98 |

- 規格の手順では判定できないが、パッシブな手がかりは観測できる要件: 21
- 偶発的な出来事（障害、更新の配信など）に頼る要件: 7

## 試験ケース単位

| 区分 | conceptual | functional | 合計 |
|---|---|---|---|
| 観測 | 0 | 0 | 0 |
| 推定 | 19 | 11 | 30 |
| 照合 | 0 | 3 | 3 |
| 判定不能 | 54 | 43 | 98 |

## TSO（カテゴリ）別の要件数

| TSO | 観測 | 推定 | 照合 | 判定不能 |
|---|---|---|---|---|
| 5.0 | 0 | 0 | 0 | 1 |
| 5.1 | 0 | 4 | 0 | 2 |
| 5.2 | 0 | 1 | 0 | 2 |
| 5.3 | 0 | 6 | 0 | 13 |
| 5.4 | 0 | 0 | 0 | 4 |
| 5.5 | 0 | 5 | 0 | 3 |
| 5.6 | 0 | 0 | 0 | 10 |
| 5.7 | 0 | 0 | 0 | 2 |
| 5.8 | 0 | 3 | 0 | 0 |
| 5.9 | 0 | 1 | 0 | 2 |
| 5.10 | 0 | 0 | 0 | 1 |
| 5.11 | 0 | 0 | 0 | 4 |
| 5.12 | 0 | 0 | 0 | 3 |
| 5.13 | 0 | 0 | 0 | 2 |
| 6 | 0 | 6 | 0 | 3 |

## 要件ごとの一覧

| 試験グループ | 区分 | 判定の向き | 手順外の手がかり | Quarant の対応機能 |
|---|---|---|---|---|
| 5.0-1 | 判定不能 | 判定できない |  |  |
| 5.1-1 | 判定不能 | 判定できない | あり | I2_HTTP_ADMIN_INTERFACE_SUSPECTED, I3_MANAGEMENT_API_EXPOSED, INSECURE_HTTP_AUTH, INSECURE_MQTT_CREDENTIALS, INSECURE_TELNET, INSECURE_TELNET_CREDENTIALS |
| 5.1-2 | 推定 | 不合格のみ | あり | INSECURE_HTTP_AUTH, INSECURE_MQTT_CREDENTIALS, INSECURE_TELNET_CREDENTIALS |
| 5.1-2A | 推定 | 不合格のみ |  | I3_API_OVER_PLAINTEXT, INSECURE_HTTP_AUTH, INSECURE_HTTP_TOKEN, INSECURE_MQTT_CREDENTIALS |
| 5.1-3 | 推定 | 不合格のみ | あり | I7_TLS_CERTIFICATE_ANOMALY_OBSERVED, I7_TLS_WEAK_CIPHER_OFFERED, I7_TLS_WEAK_CIPHER_SELECTED, I7_TLS_WEAK_VERSION_OBSERVED, TLS_CLIENT_HELLO |
| 5.1-4 | 推定 | 合格のみ |  |  |
| 5.1-5 | 判定不能 | 判定できない | あり | I2_*_SERVICE_OBSERVED, I2_HTTP_ADMIN_INTERFACE_SUSPECTED, I3_MANAGEMENT_API_EXPOSED, INSECURE_TELNET |
| 5.2-1 | 推定 | 合否とも |  |  |
| 5.2-2 | 判定不能 | 判定できない | あり |  |
| 5.2-3 | 判定不能 | 判定できない |  |  |
| 5.3-1 | 推定 | 不合格のみ | あり | I4_FIRMWARE_UPDATE_OBSERVED, I4_INSECURE_FIRMWARE_UPDATE_HTTP, I4_SUSPICIOUS_UPDATE_SOURCE |
| 5.3-2 | 推定 | 不合格のみ | あり | I4_FIRMWARE_UPDATE_OBSERVED, I4_INSECURE_FIRMWARE_UPDATE_HTTP, I4_SUSPICIOUS_UPDATE_SOURCE |
| 5.3-3 | 判定不能 | 判定できない | あり | I4_FIRMWARE_UPDATE_OBSERVED |
| 5.3-4A | 推定 | 合格のみ | あり | I4_FIRMWARE_UPDATE_OBSERVED, PERIODIC_COMMUNICATION_OBSERVED |
| 5.3-4B | 判定不能 | 判定できない |  |  |
| 5.3-5 | 判定不能 | 判定できない | あり | I4_WEAK_UPDATE_VISIBILITY, PERIODIC_COMMUNICATION_OBSERVED |
| 5.3-6A | 判定不能 | 判定できない |  |  |
| 5.3-6B | 判定不能 | 判定できない |  |  |
| 5.3-7 | 推定 | 不合格のみ |  |  |
| 5.3-8 | 判定不能 | 判定できない | あり |  |
| 5.3-9 | 判定不能 | 判定できない |  |  |
| 5.3-10 | 判定不能 | 判定できない | あり | I4_FIRMWARE_UPDATE_OBSERVED, I4_INSECURE_FIRMWARE_UPDATE_HTTP, I4_SUSPICIOUS_UPDATE_SOURCE |
| 5.3-11 | 判定不能 | 判定できない |  |  |
| 5.3-12 | 判定不能 | 判定できない |  |  |
| 5.3-13 | 推定 | 合否とも |  | dhcp_vendor_class, mdns_*, ssdp_server/location |
| 5.3-14 | 推定 | 合否とも |  |  |
| 5.3-15A | 判定不能 | 判定できない | あり | PERSISTENT_CONNECTION_ATTEMPTS |
| 5.3-15B | 判定不能 | 判定できない |  |  |
| 5.3-16 | 判定不能 | 判定できない | あり | mdns_*, ssdp_server/location |
| 5.4-1 | 判定不能 | 判定できない |  |  |
| 5.4-2 | 判定不能 | 判定できない |  |  |
| 5.4-3 | 判定不能 | 判定できない | あり | I5_KNOWN_VULNERABLE_COMPONENT |
| 5.4-4 | 判定不能 | 判定できない | あり |  |
| 5.5-1 | 推定 | 不合格のみ | あり | I7_TLS_CERTIFICATE_ANOMALY_OBSERVED, I7_TLS_ONLY_LEGACY_CIPHERS_OFFERED, I7_TLS_WEAK_CIPHER_OFFERED, I7_TLS_WEAK_CIPHER_SELECTED, I7_TLS_WEAK_CIPHER_SUITE_OBSERVED, I7_TLS_WEAK_VERSION_OBSERVED, TLS_CLIENT_HELLO |
| 5.5-2 | 判定不能 | 判定できない | あり | TLS_CLIENT_HELLO, dhcp_vendor_class, observed_ports/protocols, ssdp_server/location |
| 5.5-3 | 判定不能 | 判定できない | あり |  |
| 5.5-4 | 推定 | 不合格のみ |  | I2_HTTP_ADMIN_INTERFACE_SUSPECTED, I3_API_OVER_PLAINTEXT, I3_MANAGEMENT_API_EXPOSED, I7_TLS_CERTIFICATE_ANOMALY_OBSERVED, I7_TLS_ONLY_LEGACY_CIPHERS_OFFERED, I7_TLS_WEAK_CIPHER_OFFERED, I7_TLS_WEAK_CIPHER_SELECTED, I7_TLS_WEAK_CIPHER_SUITE_OBSERVED, I7_TLS_WEAK_VERSION_OBSERVED, INSECURE_HTTP, INSECURE_HTTP_AUTH, TLS_CLIENT_HELLO |
| 5.5-5 | 推定 | 不合格のみ |  | I2_*_PROTOCOL_EVIDENCE, I2_*_SERVICE_OBSERVED, I2_HTTP_ADMIN_INTERFACE_SUSPECTED, I3_MANAGEMENT_API_EXPOSED, INSECURE_HTTP_AUTH, observed_ports/protocols |
| 5.5-6 | 推定 | 不合格のみ | あり | I3_AUTH_TOKEN_IN_URL, I7_TLS_CERTIFICATE_ANOMALY_OBSERVED, I7_TLS_ONLY_LEGACY_CIPHERS_OFFERED, I7_TLS_WEAK_CIPHER_OFFERED, I7_TLS_WEAK_CIPHER_SELECTED, I7_TLS_WEAK_CIPHER_SUITE_OBSERVED, I7_TLS_WEAK_VERSION_OBSERVED, INSECURE_HTTP_AUTH, INSECURE_HTTP_TOKEN, INSECURE_MQTT_CREDENTIALS, INSECURE_TELNET_CREDENTIALS, TLS_CLIENT_HELLO |
| 5.5-7 | 推定 | 不合格のみ | あり | I3_AUTH_TOKEN_IN_URL, I7_TLS_CERTIFICATE_ANOMALY_OBSERVED, I7_TLS_ONLY_LEGACY_CIPHERS_OFFERED, I7_TLS_WEAK_CIPHER_OFFERED, I7_TLS_WEAK_CIPHER_SELECTED, I7_TLS_WEAK_CIPHER_SUITE_OBSERVED, I7_TLS_WEAK_VERSION_OBSERVED, INSECURE_HTTP_AUTH, INSECURE_HTTP_TOKEN, INSECURE_MQTT_CREDENTIALS, INSECURE_TELNET_CREDENTIALS, TLS_CLIENT_HELLO |
| 5.5-8 | 判定不能 | 判定できない |  |  |
| 5.6-1 | 判定不能 | 判定できない | あり | I2_*_PROTOCOL_EVIDENCE, I2_*_SERVICE_OBSERVED, I2_INSECURE_SERVICE_TO_PUBLIC_NETWORK, I9_SETUP_ENDPOINT_STILL_ACTIVE, observed_ports/protocols |
| 5.6-2 | 判定不能 | 判定できない | あり | I2_HTTP_ADMIN_INTERFACE_SUSPECTED, INSECURE_HTTP, dhcp_vendor_class, hostname (DHCP/mDNS), mdns_*, ssdp_server/location |
| 5.6-3 | 判定不能 | 判定できない |  |  |
| 5.6-4A | 判定不能 | 判定できない |  |  |
| 5.6-4B | 判定不能 | 判定できない |  |  |
| 5.6-5 | 判定不能 | 判定できない | あり | I2_*_SERVICE_OBSERVED |
| 5.6-6 | 判定不能 | 判定できない |  |  |
| 5.6-7 | 判定不能 | 判定できない |  |  |
| 5.6-8 | 判定不能 | 判定できない |  |  |
| 5.6-9 | 判定不能 | 判定できない |  |  |
| 5.7-1 | 判定不能 | 判定できない |  |  |
| 5.7-2 | 判定不能 | 判定できない | あり | PERIODIC_COMMUNICATION_OBSERVED, dns_queries |
| 5.8-1 | 推定 | 不合格のみ | あり | I6_*, I7_TLS_CERTIFICATE_ANOMALY_OBSERVED, I7_TLS_ONLY_LEGACY_CIPHERS_OFFERED, I7_TLS_WEAK_CIPHER_OFFERED, I7_TLS_WEAK_CIPHER_SELECTED, I7_TLS_WEAK_CIPHER_SUITE_OBSERVED, I7_TLS_WEAK_VERSION_OBSERVED, TLS_CLIENT_HELLO |
| 5.8-2 | 推定 | 不合格のみ | あり | I6_*, I7_TLS_CERTIFICATE_ANOMALY_OBSERVED, I7_TLS_ONLY_LEGACY_CIPHERS_OFFERED, I7_TLS_WEAK_CIPHER_OFFERED, I7_TLS_WEAK_CIPHER_SELECTED, I7_TLS_WEAK_CIPHER_SUITE_OBSERVED, I7_TLS_WEAK_VERSION_OBSERVED, TLS_CLIENT_HELLO |
| 5.8-3 | 推定 | 不合格のみ |  |  |
| 5.9-1 | 判定不能 | 判定できない | あり | IP_MAC_BINDING_CHANGED, PERIODIC_COMMUNICATION_OBSERVED, PERSISTENT_CONNECTION_ATTEMPTS |
| 5.9-2 | 推定 | 不合格のみ |  | IP_MAC_BINDING_CHANGED, PERIODIC_COMMUNICATION_OBSERVED, PERSISTENT_CONNECTION_ATTEMPTS |
| 5.9-3 | 判定不能 | 判定できない | あり | PERIODIC_COMMUNICATION_OBSERVED, PERSISTENT_CONNECTION_ATTEMPTS |
| 5.10-1 | 判定不能 | 判定できない | あり |  |
| 5.11-1 | 判定不能 | 判定できない |  |  |
| 5.11-2 | 判定不能 | 判定できない |  |  |
| 5.11-3 | 判定不能 | 判定できない |  |  |
| 5.11-4 | 判定不能 | 判定できない |  |  |
| 5.12-1 | 判定不能 | 判定できない |  |  |
| 5.12-2 | 判定不能 | 判定できない |  |  |
| 5.12-3 | 判定不能 | 判定できない |  |  |
| 5.13-1A | 判定不能 | 判定できない |  |  |
| 5.13-1B | 判定不能 | 判定できない | あり | I2_*_SERVICE_OBSERVED, observed_ports/protocols |
| 6-1 | 推定 | 不合格のみ |  | I3_UNEXPECTED_CLOUD_ENDPOINT, I6_*, TLS_CLIENT_HELLO, dns_queries |
| 6-2 | 判定不能 | 判定できない |  |  |
| 6-3A | 判定不能 | 判定できない |  |  |
| 6-3B | 判定不能 | 判定できない |  |  |
| 6-4 | 推定 | 不合格のみ |  | I6_*, INSECURE_HTTP_BODY_SECRET |
| 6-5 | 推定 | 不合格のみ |  | I3_UNEXPECTED_CLOUD_ENDPOINT, I6_*, PERIODIC_COMMUNICATION_OBSERVED, TLS_CLIENT_HELLO, dns_queries |
| 6-6 | 推定 | 不合格のみ | あり | I6_*, INSECURE_HTTP_BODY_SECRET, INSECURE_MQTT_PAYLOAD_SECRET |
| 6-7 | 推定 | 不合格のみ | あり | I6_*, INSECURE_MQTT_PAYLOAD_SECRET |
| 6-8 | 推定 | 不合格のみ | あり | I6_* |
