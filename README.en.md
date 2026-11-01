# ip-reputation-check

> Multi-source IP **screening** with **per-field confidence** and an **optional real-probe mode**.
> Pure Python standard library; usable as an agent **skill** (one command per IP). Windows no-install `.exe` included.

> ⚠️ **Positioning: multi-source screening + confidence hints — NOT an authoritative risk/security verdict.**
> Free sources are limited; for strict risk control use commercial APIs (MaxMind, IPQualityScore, Spur, VirusTotal, Spamhaus, Talos).

## 30-second usage

```bash
python scripts/ipcheck.py 8.8.8.8            # just give an IP (no subcommand needed)
python scripts/ipcheck.py 8.8.8.8 --brief    # one-line summary
```

Zero-config by default (≈10 keyless sources). Only add a **free** key if you want the extra metrics:

| You want | Extra |
|----------|-------|
| Base: geo / ASN / proxy / VPN / hosting / fraud score / rule-score | none |
| Keyless abuse signals (StopForumSpam / blocklist.de / IPsum / Spamhaus / DB-IP) | none, shown automatically |
| iphub proxy detail | free `IPHUB_API_KEY`, or `scripts/iphub_browser.py` (manual captcha) |
| AbuseIPDB abuse confidence | free `ABUSEIPDB_API_KEY` (web UI is keyless for humans; automation is Cloudflare-blocked) |
| VirusTotal | optional `VIRUSTOTAL_API_KEY` |
| MaxMind GeoLite2 (most authoritative geo) | free License Key + `maxminddb` |

## Features

- **Sources**: ipinfo, ip-api, ipwho.is, proxycheck, scamalytics, iphub, AbuseIPDB, StopForumSpam, blocklist.de, IPsum, **Spamhaus DNSBL**, **VirusTotal**, **DB-IP**, **MaxMind GeoLite2**, **RDAP**, **RIPEstat (BGP)**, **Tor official exit list**.
- **Confidence**: source tiers A/B/C × agreement → per-field 高/中/低; conflicts are shown, not hidden.
- **Evidence**: per-field support/oppose sources + strength; registry (RDAP) vs routing (BGP) kept separate.
- **IP type**: residential / mobile / datacenter / business / education / government / Tor / VPN / proxy.
- **Platform fit**: social / AI / ecommerce / streaming categories + 15 named platforms (rule-based, not tested).
- **No-mislead**: no data / empty response → **"unknown / cannot judge"** (never "clean"); private/reserved IPs skipped locally; Spamhaus Fake-IP → "untrusted"; PBL policy list ≠ malicious.
- **Real probe (opt-in)**: `probe` / `check --probe` sends read-only requests from the egress (or `--proxy`), with layered statuses and an egress-vs-target guard. 200≠usable, 403≠banned, 401 may just be missing a key.
- **Ops**: batch `--file`, CSV `--csv`, monitoring `watch`, source health `health`, self-tests + CI matrix (3.8/3.10/3.12, Windows).

## Commands

```bash
python scripts/ipcheck.py check <IP...> [--file F] [--csv out.csv] [--json] [--brief] [--env] [--no-platforms] [--regions] [--probe] [--proxy URL] [--interval S] [--only ...]
python scripts/ipcheck.py probe [--proxy URL] [--expect-ip IP] [--only google,openai,x,...]
python scripts/ipcheck.py health [--ip IP] [--only src,...]
python scripts/ipcheck.py open <IP> [--all]            # open pre-filled web pages for manual check
python scripts/ipcheck.py myip [--json]                # egress IP + timezone/DNS consistency
python scripts/ipcheck.py stability [--rounds N] [--interactive]
python scripts/ipcheck.py watch [IP...] [--egress] [--interval 60]
```

`--only` sources: `ipinfo,ipapi,ipwhois,proxycheck,scamalytics,iphub,abuseipdb,stopforumspam,blocklistde,ipsum,spamhaus,virustotal,dbip,maxmind,rdap,ripe_bgp,tor_exit`

## Env keys (all optional)

`IPHUB_API_KEY`, `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `IPINFO_TOKEN`, `SCAMALYTICS_USER`+`SCAMALYTICS_KEY`, `IPHUB_TURNSTILE_TOKEN`, `GEOIP2_MMDB`, `IPCHECK_GATEWAY`, `IPCHECK_GATEWAY_TOKEN`, `IPCHECK_PROXY`.

## Requirements

- Base tool: **Python 3.8+**, **no pip packages** (stdlib only). No Node, no browser.
- Windows no-install: use `dist/ipcheck.exe` (no Python needed).
- `--browser` / `iphub_browser.py` only: Playwright + Chrome.
- MaxMind: `pip install maxminddb` + `python scripts/setup_geoip.py --license-key KEY`.

## What it can / cannot tell you

| Dimension | Reliability (free) |
|-----------|--------------------|
| Network registration (RDAP) / routing (BGP) / ASN | relatively high |
| Country | high; city ~50–80% (not physical location) |
| Proxy/VPN/hosting | partial; residential proxies are often missed |
| Abuse records | partial; **absence ≠ clean** |
| Real usability per platform | only via `probe` from that egress |

**It cannot reliably tell you** whether an IP is dedicated residential, whether an account will be banned, or long-term stability. Use it as a *query aggregator + evidence viewer*, not a *security verdict engine*.

## Tests

```bash
python tests/test_core.py
python tests/test_fixtures.py
python tests/test_consistency.py
```

## License

MIT © 2026 FelixDSH
