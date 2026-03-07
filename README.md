# Quarant

**Quarant** は、ホームネットワーク内の IoT デバイスを保護するためのカスタムセキュリティゲートウェイです。

## OWASP IoT Top 10 (2018) 対応状況

- [ ] I1: Weak, Guessable, or Hardcoded Passwords
- [ ] I2: Insecure Network Services
- [ ] I3: Insecure Ecosystem Interfaces
- [ ] I4: Lack of Secure Update Mechanism
- [ ] I5: Use of Insecure or Outdated Components
- [ ] I6: Insufficient Privacy Protection
- [x] I7: Insecure Data Transfer and Storage
- [ ] I8: Lack of Device Management
- [ ] I9: Insecure Default Settings
- [ ] I10: Lack of Physical Hardening

## I7: Insecure Data Transfer and Storage

アプリケーション層の通信を解析し、以下を検知します。

### 検知機能

- 平文 HTTP 通信の検知
- HTTP Header に含まれる認証情報の検知
- URL Query に含まれる機密情報の検知
- HTTP Body に含まれる機密情報の検知  
  - `application/x-www-form-urlencoded`
  - `application/json`
- TLS ClientHello の解析
- JA3 フィンガープリント生成
- HTTP / TLS メタデータによるデバイス推定

---
