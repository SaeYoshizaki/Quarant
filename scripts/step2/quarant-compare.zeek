# Zeek's shipped site/local.zeek without frameworks/files/detect-MHR, which
# queries Team Cymru's Malware Hash Registry over DNS (external data
# transfer). Everything else is the stock policy. Passwords stay unlogged
# (HTTP::default_capture_password keeps its default F).
@load misc/loaded-scripts
@load misc/capture-loss
@load misc/stats
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load-sigs frameworks/signatures/detect-windows-shells
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
@load protocols/dns/detect-external-names
@load protocols/ftp/detect
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs
@load protocols/ssl/validate-certs
@load protocols/ssl/log-hostcerts-only
@load protocols/ssh/geo-data
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/interesting-hostnames
@load protocols/http/detect-sql-injection
@load frameworks/files/hash-all-files
@load protocols/conn/mac-logging
@load misc/detect-traceroute
