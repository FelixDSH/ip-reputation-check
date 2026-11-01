# -*- coding: utf-8 -*-
# 由 tools/make_pkg.py 从 ipcheck.py 自动拆分生成，请勿手改结构注释。
import argparse
import concurrent.futures as cf
import csv
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from ipcheck_lib.constants import *  # noqa: F401,F403
from ipcheck_lib.http import *  # noqa: F401,F403

ALL_SOURCES = ["ipinfo", "ipapi", "ipwhois", "proxycheck", "scamalytics",
               "iphub", "abuseipdb", "stopforumspam", "blocklistde", "ipsum",
               "spamhaus", "virustotal", "dbip", "maxmind"]

def src_ipinfo(ip, timeout):
    token = os.environ.get("IPINFO_TOKEN", "").strip()
    q = "/json" + (("?token=" + urllib.parse.quote(token)) if token else "")
    _, txt = http_get("https://ipinfo.io/%s%s" % (ip, q), timeout=timeout)
    d = _j(txt)
    if "bogon" in d or d.get("error"):
        raise RuntimeError(d.get("error", {}).get("message") if isinstance(d.get("error"), dict) else d.get("error") or "bogon")
    lat, lon = (None, None)
    if d.get("loc") and "," in d["loc"]:
        lat, lon = d["loc"].split(",", 1)
    return {
        "country": d.get("country"), "region": d.get("region"),
        "city": d.get("city"), "lat": lat, "lon": lon,
        "timezone": d.get("timezone"), "asn_org": d.get("org"),
        "hostname": d.get("hostname"),
    }

def src_ipapi(ip, timeout):
    fields = ("status,message,country,countryCode,regionName,city,lat,lon,"
              "timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
    _, txt = http_get("http://ip-api.com/json/%s?fields=%s" % (ip, fields),
                      timeout=timeout)
    d = _j(txt)
    if d.get("status") != "success":
        raise RuntimeError(d.get("message") or "query failed")
    return {
        "country": d.get("country"), "country_code": d.get("countryCode"),
        "region": d.get("regionName"), "city": d.get("city"),
        "lat": d.get("lat"), "lon": d.get("lon"), "timezone": d.get("timezone"),
        "isp": d.get("isp"), "org": d.get("org"), "asn_org": d.get("as"),
        "asname": d.get("asname"), "hostname": d.get("reverse"),
        "proxy": d.get("proxy"), "hosting": d.get("hosting"),
        "mobile": d.get("mobile"),
    }

def src_ipwhois(ip, timeout):
    _, txt = http_get("https://ipwho.is/%s" % ip, timeout=timeout)
    d = _j(txt)
    if not d.get("success", True):
        raise RuntimeError(d.get("message") or "query failed")
    conn = d.get("connection") or {}
    return {
        "country": d.get("country"), "country_code": d.get("country_code"),
        "region": d.get("region"), "city": d.get("city"),
        "lat": d.get("latitude"), "lon": d.get("longitude"),
        "timezone": (d.get("timezone") or {}).get("id"),
        "isp": conn.get("isp"), "org": conn.get("org"),
        "asn": conn.get("asn"), "domain": conn.get("domain"),
    }

def src_proxycheck(ip, timeout):
    url = "https://proxycheck.io/v2/%s?vpn=1&asn=1&risk=1" % ip
    _, txt = http_get(url, timeout=timeout)
    d = _j(txt)
    if d.get("status") != "ok":
        raise RuntimeError(d.get("message") or "query failed")
    node = d.get(ip) or {}
    if not node:
        # proxycheck 有时把结果放在第一个非 status 键
        for k, v in d.items():
            if k != "status" and isinstance(v, dict):
                node = v
                break
    ptype = node.get("type")
    proxy = node.get("proxy")
    return {
        "proxy": (proxy == "yes") if proxy is not None else None,
        "type": ptype,
        "provider": node.get("provider"),
        "organisation": node.get("organisation"),
        "asn": node.get("asn"),
        "country": node.get("country"), "country_code": node.get("isocode"),
        "region": node.get("region"), "city": node.get("city"),
        "risk": node.get("risk"),
        "vpn": (str(ptype).lower() in ("vpn",)) if ptype else None,
        "hosting": (str(ptype).lower() in ("hosting", "business")) if ptype else None,
    }

def src_scamalytics(ip, timeout):
    # 优先 API（若有 key），否则解析网页
    user = os.environ.get("SCAMALYTICS_USER", "").strip()
    key = os.environ.get("SCAMALYTICS_KEY", "").strip()
    if user and key:
        url = ("https://api11.scamalytics.com/v3/%s/?key=%s&ip=%s"
               % (urllib.parse.quote(user), urllib.parse.quote(key), ip))
        _, txt = http_get(url, timeout=timeout)
        d = _j(txt)
        sc = (d.get("scamalytics") or d.get("score") or {})
        score = sc.get("scamalytics_score", d.get("scamalytics_score"))
        risk = sc.get("risk", d.get("risk"))
        return {"fraud_score": _to_int(score), "risk": risk, "via": "api"}

    _, txt = http_get("https://scamalytics.com/ip/%s" % ip, timeout=timeout,
                      headers={"Accept": "text/html"})
    score = None
    risk = None
    m = re.search(r"Fraud Score[^0-9]{0,60}(\d+)", txt, re.I)
    if m:
        score = int(m.group(1))
    m2 = re.search(r"(Very Low|Low|Medium|High|Very High)\s*Risk", txt, re.I)
    if m2:
        risk = m2.group(1).title()
    if score is None and risk is None:
        raise RuntimeError("页面未解析到 Fraud Score（可能被拦截或改版）")
    return {"fraud_score": score, "risk": risk, "via": "html"}

def src_iphub(ip, timeout):
    """有 key 走官方 v2 API；无 key 走网站游客接口 POST /api/lookup/ip。
    游客接口对高信誉出口直接出结果，对机房/VPN 出口可能返回 Turnstile 人机验证。"""
    key = os.environ.get("IPHUB_API_KEY", "").strip()
    api_err = None
    if key:
        try:
            _, txt = http_get("https://v2.api.iphub.info/ip/%s" % ip,
                              headers={"X-Key": key}, timeout=timeout)
            d = _j(txt)
            if d.get("error"):
                raise RuntimeError(str(d.get("error")))
            block = d.get("block")
            return {
                "block": block,
                "proxy": (block == 1) if block is not None else None,
                "tor": None, "hosting": None, "residential_proxy": None,
                "country_code": d.get("countryCode"), "isp": d.get("isp"),
                "asn": d.get("asn"), "via": "api",
            }
        except Exception as e:  # noqa: BLE001
            api_err = e  # 有 key 但失败则回退游客接口

    token = os.environ.get("IPHUB_TURNSTILE_TOKEN", "").strip() or None
    body = {"ip": ip, "apiKeyID": "guest", "cf-turnstile-response": token}
    _, txt = http_post_json("https://iphub.info/api/lookup/ip", body, headers={
        "Origin": "https://iphub.info", "Referer": "https://iphub.info/"}, timeout=timeout)
    d = _j(txt)
    if d.get("success"):
        data = d.get("data", {}) or {}
        pt = data.get("proxyType") or {}
        block = data.get("block")
        return {
            "block": block,
            "proxy": bool(pt.get("proxy")) or (block == 1),
            "tor": pt.get("tor"),
            "hosting": pt.get("hosting"),
            "residential_proxy": pt.get("residentialProxy"),
            "relay": pt.get("relay"),
            "cloud_gaming": pt.get("cloudGaming"),
            "country_code": data.get("countryCode"),
            "country": data.get("countryName"),
            "isp": data.get("isp"), "asn": data.get("asn"),
            "hostname": data.get("hostname"), "via": "guest",
        }
    if d.get("captchaRequired"):
        hint = ("需人机验证(Turnstile)：配 IPHUB_API_KEY，或运行 scripts/iphub_browser.py <IP>，"
                "或设 IPHUB_TURNSTILE_TOKEN（详见 README「人机验证」）")
        if api_err:
            hint += "（注：提供的 API Key 调用失败：%s）" % api_err
        raise RuntimeError(hint)
    raise RuntimeError(d.get("error") or d.get("message") or "iphub 查询失败")

def src_abuseipdb(ip, timeout):
    key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not key:
        raise RuntimeError("需免费 ABUSEIPDB_API_KEY（网页人工可查，程序化被 Cloudflare 拦，注册免费 1000/天）")
    url = ("https://api.abuseipdb.com/api/v2/check?ipAddress=%s"
           "&maxAgeInDays=90&verbose=true" % urllib.parse.quote(ip))
    _, txt = http_get(url, headers={"Key": key, "Accept": "application/json"},
                      timeout=timeout)
    d = _j(txt).get("data", {})
    return {
        "abuse_confidence": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "num_distinct_users": d.get("numDistinctUsers"),
        "last_reported": d.get("lastReportedAt"),
        "usage_type": d.get("usageType"),
        "domain": d.get("domain"), "isp": d.get("isp"),
        "country_code": d.get("countryCode"),
        "is_tor": d.get("isTor"),
    }

def src_stopforumspam(ip, timeout):
    """免 key：垃圾信息/滥用举报频率。"""
    _, txt = http_get("https://api.stopforumspam.org/api?ip=%s&json" % ip,
                      timeout=timeout)
    d = _j(txt)
    node = d.get("ip") or {}
    return {
        "frequency": _to_int(node.get("frequency")),
        "appears": _to_int(node.get("appears")),
        "lastseen": node.get("lastseen"),
        "confidence": _to_int(node.get("confidence")),
    }

def src_blocklistde(ip, timeout):
    """免 key：blocklist.de 攻击举报数。"""
    _, txt = http_get("https://api.blocklist.de/api.php?ip=%s&format=json" % ip,
                      timeout=timeout)
    d = _j(txt)
    return {"attacks": _to_int(d.get("attacks")), "reports": _to_int(d.get("reports"))}

_IPSUM_LOCK = None

_IPSUM_DATA = None

_IPSUM_TS = 0.0

_IPSUM_TTL = 12 * 3600

def _load_ipsum(timeout):
    """下载并缓存 IPsum 聚合黑名单（ip -> 命中次数）。12h 缓存。"""
    global _IPSUM_DATA, _IPSUM_TS
    now = time.time()
    if _IPSUM_DATA is not None and now - _IPSUM_TS < _IPSUM_TTL:
        return _IPSUM_DATA
    cache = os.path.join(tempfile.gettempdir(), "ipcheck_ipsum.txt")
    text = None
    if os.path.exists(cache) and now - os.path.getmtime(cache) < _IPSUM_TTL:
        try:
            with open(cache, "r", encoding="utf-8") as f:
                text = f.read()
        except Exception:
            text = None
    if text is None:
        _, text = http_get("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
                           timeout=max(timeout, 30))
        try:
            with open(cache, "w", encoding="utf-8") as f:
                f.write(text)
        except Exception:
            pass
    data = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            try:
                data[parts[0]] = int(parts[1])
            except ValueError:
                continue
    _IPSUM_DATA, _IPSUM_TS = data, now
    return data

def src_ipsum(ip, timeout):
    """免 key：IPsum 聚合黑名单是否命中及命中条数。"""
    data = _load_ipsum(timeout)
    score = data.get(ip)
    return {"listed": score is not None, "score": score or 0,
            "total_ips": len(data)}

def _dns_query_a(name, timeout):
    """在独立线程里做 DNS A 查询并限时等待，避免改全局 socket 超时（线程安全）。"""
    import threading
    box = {}

    def worker():
        try:
            box["a"] = socket.gethostbyname(name)
        except Exception as e:  # noqa: BLE001
            box["e"] = e

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout)
    if "a" in box:
        return box["a"]
    if "e" in box:
        raise box["e"]
    raise socket.timeout("dns timeout")

def src_spamhaus(ip, timeout):
    """免 key：Spamhaus ZEN DNSBL（SBL/XBL/PBL，权威反垃圾/被入侵源名单）。"""
    from ipaddress import ip_address
    try:
        a = ip_address(ip)
    except ValueError:
        raise RuntimeError("非法 IP")
    if a.version != 4:
        raise RuntimeError("Spamhaus DNSBL 仅支持 IPv4")
    rev = ".".join(reversed(ip.split("."))) + ".zen.spamhaus.org"
    try:
        ans = _dns_query_a(rev, min(timeout, 8))
    except socket.gaierror:
        return {"listed": False, "zones": [], "answer": None}
    except socket.timeout:
        raise RuntimeError("Spamhaus DNS 查询超时")
    if ans.startswith("127.255.255."):
        raise RuntimeError("Spamhaus 拒绝当前 DNS 出口（公共解析器/超量），请直连或降低频率")
    # DNSBL 正常只有两种应答：NXDOMAIN(未上榜) 或 127.0.0.x(上榜)。
    # 若解析器返回其它地址（如 Clash/Surge 的 Fake-IP 198.18.0.0/15、0.0.0.0 等），
    # 说明 DNS 被本地代理接管 → 结果不可信，必须报错而不是当成“未命中”。
    if not ans.startswith("127.0.0."):
        raise RuntimeError("DNS 返回异常(%s)，疑似 Fake-IP/本地代理 DNS，Spamhaus 结果不可信" % ans)
    # 名单语义区分：SBL/XBL(CSS)/DROP = 实际垃圾邮件/被入侵/攻击源（恶意）；
    # PBL = 发信策略名单（住宅网络常因不应直发邮件而入列，与网页/账号安全无关，不应判为恶意）。
    malicious_codes = {"127.0.0.2": "SBL", "127.0.0.3": "XBL/CSS", "127.0.0.9": "DROP"}
    policy_codes = {"127.0.0.4": "PBL", "127.0.0.5": "PBL", "127.0.0.6": "PBL",
                    "127.0.0.7": "PBL", "127.0.0.10": "PBL", "127.0.0.11": "PBL"}
    zones = []
    malicious = policy = False
    if ans in malicious_codes:
        zones = [malicious_codes[ans]]; malicious = True
    elif ans in policy_codes:
        zones = [policy_codes[ans]]; policy = True
    else:
        zones = ["UNKNOWN"]
    return {"listed": True, "zones": zones, "malicious": malicious,
            "policy": policy, "answer": ans}

def src_virustotal(ip, timeout):
    """可选 key：VirusTotal 70+ 引擎聚合判定（免费 key 限速 4/分）。"""
    key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        raise RuntimeError("未配置 VIRUSTOTAL_API_KEY（免费注册可查 70+ 引擎）")
    _, txt = http_get("https://www.virustotal.com/api/v3/ip_addresses/%s" % ip,
                      headers={"x-apikey": key}, timeout=timeout)
    d = _j(txt).get("data", {}).get("attributes", {})
    st = d.get("last_analysis_stats") or {}
    return {
        "malicious": st.get("malicious"), "suspicious": st.get("suspicious"),
        "harmless": st.get("harmless"), "undetected": st.get("undetected"),
        "reputation": d.get("reputation"), "as_owner": d.get("as_owner"),
    }

def src_dbip(ip, timeout):
    """免 key：DB-IP 免费 GeoIP API（正规 IP 数据商，地理交叉校验）。"""
    _, txt = http_get("https://api.db-ip.com/v2/free/%s" % ip, timeout=timeout)
    d = _j(txt)
    if d.get("error"):
        raise RuntimeError(str(d.get("error")))
    return {
        "country": d.get("countryName"), "country_code": d.get("countryCode"),
        "region": d.get("stateProv"), "city": d.get("city"),
    }

_MMDB_CACHE = {}

def _ascii_path(path):
    """maxminddb 的 C 扩展在 Windows 上无法打开非 ASCII 路径；转 8.3 短路径或拷到临时 ASCII 路径。"""
    if path.isascii():
        return path
    if os.name == "nt":
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(32768)
            n = ctypes.windll.kernel32.GetShortPathNameW(path, buf, 32768)
            if n and buf.value and buf.value.isascii():
                return buf.value
        except Exception:
            pass
    try:
        import tempfile
        import shutil
        dst = os.path.join(tempfile.gettempdir(), "ipcheck_geolite.mmdb")
        if (not os.path.exists(dst)) or os.path.getmtime(dst) < os.path.getmtime(path):
            shutil.copyfile(path, dst)
        return dst
    except Exception:
        return path

def _maxmind_path():
    p = os.environ.get("GEOIP2_MMDB", "").strip()
    if p and os.path.exists(p):
        return p
    base = os.path.dirname(os.path.abspath(__file__))
    for name in ("GeoLite2-City.mmdb", "GeoLite2-Country.mmdb"):
        cand = os.path.normpath(os.path.join(base, "..", "data", name))
        if os.path.exists(cand):
            return cand
    return None

def src_maxmind(ip, timeout):
    """可选：MaxMind GeoLite2 本地库（最权威地理）。需 .mmdb + maxminddb 库。"""
    path = _maxmind_path()
    if not path:
        raise RuntimeError("未配置 MaxMind：运行 scripts/setup_geoip.py --license-key KEY 下载库，或设 GEOIP2_MMDB")
    try:
        import maxminddb
    except Exception:
        raise RuntimeError("需先安装 maxminddb：pip install maxminddb")
    reader = _MMDB_CACHE.get(path)
    if reader is None:
        reader = maxminddb.open_database(_ascii_path(path))
        _MMDB_CACHE[path] = reader
    rec = reader.get(ip) or {}
    if not rec:
        raise RuntimeError("库中无此 IP")
    country = (rec.get("country") or {}).get("names", {}).get("en")
    cc = (rec.get("country") or {}).get("iso_code") or (rec.get("registered_country") or {}).get("iso_code")
    subs = rec.get("subdivisions") or []
    region = (subs[0].get("names", {}).get("en") if subs else None)
    city = (rec.get("city") or {}).get("names", {}).get("en")
    loc = rec.get("location") or {}
    traits = rec.get("traits") or {}
    return {
        "country": country, "country_code": cc, "region": region, "city": city,
        "lat": loc.get("latitude"), "lon": loc.get("longitude"),
        "timezone": loc.get("time_zone"),
        "asn": traits.get("autonomous_system_number"),
        "asn_org": traits.get("autonomous_system_organization"),
    }

SOURCES = {
    "ipinfo": src_ipinfo,
    "ipapi": src_ipapi,
    "ipwhois": src_ipwhois,
    "proxycheck": src_proxycheck,
    "scamalytics": src_scamalytics,
    "iphub": src_iphub,
    "abuseipdb": src_abuseipdb,
    "stopforumspam": src_stopforumspam,
    "blocklistde": src_blocklistde,
    "ipsum": src_ipsum,
    "spamhaus": src_spamhaus,
    "virustotal": src_virustotal,
    "dbip": src_dbip,
    "maxmind": src_maxmind,
}

def set_only_sources(names):
    """运行时覆盖启用的源（供 gateway --only 使用）。"""
    global ALL_SOURCES
    ALL_SOURCES = list(names)



__all__ = ['ALL_SOURCES', 'src_ipinfo', 'src_ipapi', 'src_ipwhois', 'src_proxycheck', 'src_scamalytics', 'src_iphub', 'src_abuseipdb', 'src_stopforumspam', 'src_blocklistde', '_IPSUM_LOCK', '_IPSUM_DATA', '_IPSUM_TS', '_IPSUM_TTL', '_load_ipsum', 'src_ipsum', '_dns_query_a', 'src_spamhaus', 'src_virustotal', 'src_dbip', '_MMDB_CACHE', '_ascii_path', '_maxmind_path', 'src_maxmind', 'SOURCES', 'set_only_sources']
