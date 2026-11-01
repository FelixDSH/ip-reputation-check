#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ipcheck.py — 多源 IP 信誉检测 / IP reputation checker
=====================================================

一次输入 IP，并发查询多个公开情报源，聚合成一张人类可读报表（或 --json 机器结果）：
  - ipinfo.io       地理 / ASN / Org
  - ip-api.com      地理 + proxy / hosting / mobile 标记（关键信号）
  - ipwho.is        地理 / ASN 备用源
  - proxycheck.io   proxy / VPN / 类型（免 key，有速率限制）
  - scamalytics.com Fraud Score 与风险等级（网页解析）
  - iphub.info      block 等级（需 IPHUB_API_KEY）
  - abuseipdb.com   Abuse Confidence Score（需 ABUSEIPDB_API_KEY）

另含连通性/稳定性测试：
  myip        多源回显，确认当前出口 IP 及其一致性
  stability   [--rounds N] 连续采样，看 IP 是否漂移
              [--interactive] 断开/重连前后对比（检测代理/VPN 出口是否稳定）

仅依赖 Python 3.8+ 标准库。

用法示例：
  python ipcheck.py check 8.8.8.8
  python ipcheck.py check 8.8.8.8 1.1.1.1 --json
  python ipcheck.py check 1.2.3.4 --only ipinfo,ipapi,proxycheck,scamalytics
  python ipcheck.py myip
  python ipcheck.py stability --rounds 5 --interval 3
  python ipcheck.py stability --interactive

API Key（可选，缺省时自动跳过对应源）：
  export IPHUB_API_KEY=xxxx
  export ABUSEIPDB_API_KEY=xxxx
  export IPINFO_TOKEN=xxxx
  export SCAMALYTICS_USER=xxxx   export SCAMALYTICS_KEY=xxxx
"""

import argparse
import concurrent.futures as cf
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0 Safari/537.36")


def _setup_console():
    """Windows 控制台默认 GBK，遇到 emoji/中文会 UnicodeEncodeError。
    启动时切 UTF-8 代码页并重配 stdout/stderr，保证任何终端都不崩。"""
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


DEFAULT_TIMEOUT = 12
ALL_SOURCES = ["ipinfo", "ipapi", "ipwhois", "proxycheck", "scamalytics",
               "iphub", "abuseipdb", "stopforumspam", "blocklistde", "ipsum"]

# 云/机房组织关键字（辅助判断 hosting）
CLOUD_HINTS = ("amazon", "aws", "google", "microsoft", "azure", "digitalocean",
               "linode", "akamai", "cloudflare", "ovh", "hetzner", "vultr",
               "alibaba", "aliyun", "tencent", "oracle", "gcore", "leaseweb",
               "choopa", "contabo", "hosting", "datacenter", "data center",
               "server", "colo")


# --------------------------------------------------------------------------- #
# HTTP 基础
# --------------------------------------------------------------------------- #
def _make_opener():
    ctx = ssl.create_default_context()
    # 部分环境证书链不全，宽松但不关闭校验的主体行为
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except Exception:
        pass
    return urllib.request.build_opener(
        urllib.request.ProxyHandler(),          # 尊重系统代理 / 环境变量
        urllib.request.HTTPSHandler(context=ctx),
    )


_OPENER = _make_opener()


def http_get(url, headers=None, timeout=DEFAULT_TIMEOUT, retries=1):
    """返回 (status, text)。失败抛异常。"""
    h = {"User-Agent": UA, "Accept": "application/json, text/html, */*"}
    if headers:
        h.update(headers)
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=h)
            with _OPENER.open(req, timeout=timeout) as resp:
                raw = resp.read()
                enc = resp.headers.get_content_charset() or "utf-8"
                return resp.status, raw.decode(enc, "replace")
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt < retries:
                time.sleep(0.6 * (attempt + 1))
    raise last


def _j(text):
    return json.loads(text)


def http_post_json(url, body_obj, headers=None, timeout=DEFAULT_TIMEOUT, retries=1):
    """POST JSON，返回 (status, text)。"""
    h = {"User-Agent": UA, "Accept": "application/json",
         "Content-Type": "application/json"}
    if headers:
        h.update(headers)
    payload = json.dumps(body_obj).encode("utf-8")
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=payload, headers=h, method="POST")
            with _OPENER.open(req, timeout=timeout) as resp:
                raw = resp.read()
                enc = resp.headers.get_content_charset() or "utf-8"
                return resp.status, raw.decode(enc, "replace")
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read().decode("utf-8", "replace")
            except Exception:
                last = e
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt < retries:
                time.sleep(0.6 * (attempt + 1))
    raise last


# --------------------------------------------------------------------------- #
# 各情报源：统一返回 {source, ok, data, error}
# --------------------------------------------------------------------------- #
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
}

SOURCE_LABEL = {
    "ipinfo": "ipinfo.io", "ipapi": "ip-api.com", "ipwhois": "ipwho.is",
    "proxycheck": "proxycheck.io", "scamalytics": "scamalytics.com",
    "iphub": "iphub.info", "abuseipdb": "abuseipdb.com",
    "stopforumspam": "stopforumspam.com", "blocklistde": "blocklist.de",
    "ipsum": "IPsum(聚合黑名单)",
}


def _to_int(v):
    try:
        return int(float(v))
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# 聚合
# --------------------------------------------------------------------------- #
def _pick(*vals):
    for v in vals:
        if v is not None and v != "" and v is not False:
            return v
    return None


def _coherent_geo(sources):
    """从单一来源取一整套地理字段，避免跨源拼接导致的不一致。"""
    order = ["ipapi", "ipinfo", "ipwhois", "proxycheck"]
    for s in order:
        d = sources.get(s) or {}
        if d.get("country") and (d.get("city") or d.get("region")):
            return {
                "country": d.get("country"),
                "country_code": d.get("country_code"),
                "region": d.get("region"),
                "city": d.get("city"),
                "lat": d.get("lat"), "lon": d.get("lon"),
                "timezone": d.get("timezone"),
                "geo_source": SOURCE_LABEL.get(s, s),
            }
    # 兜底：字段级拼接
    return {
        "country": _pick(*[sources.get(s, {}).get("country") for s in order]),
        "country_code": _pick(*[sources.get(s, {}).get("country_code") for s in order]),
        "region": _pick(*[sources.get(s, {}).get("region") for s in order]),
        "city": _pick(*[sources.get(s, {}).get("city") for s in order]),
        "lat": _pick(*[sources.get(s, {}).get("lat") for s in order]),
        "lon": _pick(*[sources.get(s, {}).get("lon") for s in order]),
        "timezone": _pick(*[sources.get(s, {}).get("timezone") for s in order]),
        "geo_source": None,
    }


def _vote(conflicts, flag_name, votes):
    """votes=[(source, value)]；按给定顺序取第一个已知值，并记录源间冲突。"""
    known = [(s, v) for s, v in votes if v is not None]
    if not known:
        return None
    val = known[0][1]
    if any(v != val for _, v in known):
        detail = ", ".join("%s=%s" % (SOURCE_LABEL.get(s, s), ("是" if v else "否")) for s, v in known)
        conflicts.append("%s 源间不一致（%s），采用 %s" % (flag_name, detail, SOURCE_LABEL.get(known[0][0], known[0][0])))
    return val


def aggregate(ip, results):
    get = {r["source"]: r for r in results}
    srcs = {name: (get[name]["data"] if get.get(name) and get[name]["ok"] else {})
            for name in SOURCES}

    ipinfo, ipapi, ipwho = srcs["ipinfo"], srcs["ipapi"], srcs["ipwhois"]
    proxycheck, scam = srcs["proxycheck"], srcs["scamalytics"]
    iphub, abuse = srcs["iphub"], srcs["abuseipdb"]
    sfs = srcs["stopforumspam"]
    bl = srcs["blocklistde"]
    ipsum = srcs["ipsum"]

    geo = _coherent_geo(srcs)
    asn_org = _pick(ipinfo.get("asn_org"), ipapi.get("asn_org"), ipwho.get("org"),
                    (("AS%s " % ipwho.get("asn")) if ipwho.get("asn") else None),
                    proxycheck.get("asn"))
    isp = _pick(ipapi.get("isp"), ipwho.get("isp"), proxycheck.get("provider"), iphub.get("isp"))
    hostname = _pick(ipapi.get("hostname"), ipinfo.get("hostname"))

    conflicts = []
    # 代理：优先专用代理库 proxycheck，其次 iphub，最后 ip-api
    proxy = _vote(conflicts, "Proxy", [
        ("proxycheck", proxycheck.get("proxy")),
        ("iphub", iphub.get("proxy")),
        ("ipapi", ipapi.get("proxy")),
    ])
    # VPN
    vpn = _vote(conflicts, "VPN", [
        ("proxycheck", proxycheck.get("vpn")),
        ("iphub", (True if iphub.get("block") in (1,) else None)),
    ])
    # 托管：ip-api 的 hosting 最直接，其次 proxycheck 类型，最后按组织关键字推断
    hosting = _vote(conflicts, "Hosting", [
        ("ipapi", ipapi.get("hosting")),
        ("proxycheck", proxycheck.get("hosting")),
        ("iphub", iphub.get("hosting")),
        ("ipinfo", _hosting_from_org(asn_org or isp)),
    ])
    mobile = ipapi.get("mobile") if ipapi.get("mobile") is not None else None
    tor = _pick_bool(abuse.get("is_tor"), iphub.get("tor"))

    fraud_score = _to_int(scam.get("fraud_score"))
    fraud_risk = scam.get("risk")
    abuse_conf = _to_int(abuse.get("abuse_confidence"))

    # 免 key 举报类渠道汇总
    sfs_freq = _to_int(sfs.get("frequency"))
    bl_attacks = _to_int(bl.get("attacks"))
    ipsum_listed = bool(ipsum.get("listed"))
    ipsum_score = _to_int(ipsum.get("score"))
    free_pts = 0
    if sfs_freq and sfs_freq > 0:
        free_pts = max(free_pts, min(30, 10 + sfs_freq))
    if bl_attacks and bl_attacks > 0:
        free_pts = max(free_pts, min(50, 10 + bl_attacks * 5))
    if ipsum_listed:
        free_pts = max(free_pts, min(50, 15 + (ipsum_score or 1) * 3))

    risk_score, risk_level = compute_risk(fraud_score, abuse_conf, proxy, vpn, hosting,
                                           tor, mobile, free_pts)

    return {
        "ip": ip,
        "geo": geo,
        "network": {"asn_org": asn_org, "isp": isp, "hostname": hostname,
                    "usage_type": abuse.get("usage_type"), "type": proxycheck.get("type")},
        "flags": {"proxy": proxy, "vpn": vpn, "hosting": hosting, "mobile": mobile,
                  "tor": tor, "residential_proxy": iphub.get("residential_proxy")},
        "scores": {"fraud_score": fraud_score, "fraud_risk": fraud_risk,
                   "abuse_confidence": abuse_conf,
                   "abuse_reports": _to_int(abuse.get("total_reports")),
                   "proxycheck_risk": _to_int(proxycheck.get("risk")),
                   "iphub_block": iphub.get("block"),
                   "sfs_frequency": sfs_freq, "bl_attacks": bl_attacks,
                   "ipsum_listed": ipsum_listed, "ipsum_score": ipsum_score},
        "verdict": {"risk_score": risk_score, "risk_level": risk_level,
                    "label": risk_label(risk_level)},
        "conflicts": conflicts,
        "sources": results,
    }


def _pick_bool(*vals):
    for v in vals:
        if v is True:
            return True
    for v in vals:
        if v is False:
            return False
    return None


def _hosting_from_org(s):
    if not s:
        return None
    low = str(s).lower()
    return True if any(k in low for k in CLOUD_HINTS) else None


def compute_risk(fraud, abuse, proxy, vpn, hosting, tor, mobile, free_pts=0):
    ext = max([x for x in (fraud, abuse) if x is not None], default=0)
    pts = 0
    if proxy:
        pts += 30
    if vpn:
        pts += 35
    if hosting:
        pts += 10
    if tor:
        pts += 60
    if mobile:
        pts -= 5
    pts = max(0, pts)
    score = min(100, max(ext, pts, free_pts))
    if score < 20:
        level = "clean"
    elif score < 50:
        level = "low"
    elif score < 80:
        level = "medium"
    else:
        level = "high"
    return score, level


def risk_label(level):
    return {
        "clean": "\U0001F7E2 干净 / 低风险",
        "low": "\U0001F7E1 中低风险",
        "medium": "\U0001F7E0 中高风险",
        "high": "\U0001F534 高风险",
    }.get(level, level)


# --------------------------------------------------------------------------- #
# 单个 IP 的完整检测
# --------------------------------------------------------------------------- #
def check_ip(ip, only=None, timeout=DEFAULT_TIMEOUT):
    names = [s for s in (only or ALL_SOURCES) if s in SOURCES]
    results = []
    with cf.ThreadPoolExecutor(max_workers=len(names)) as ex:
        futs = {ex.submit(SOURCES[n], ip, timeout): n for n in names}
        for fut in cf.as_completed(futs):
            n = futs[fut]
            try:
                d = fut.result()
                results.append({"source": n, "ok": True, "data": d, "error": None})
            except Exception as e:  # noqa: BLE001
                results.append({"source": n, "ok": False, "data": {}, "error": str(e)})
    # 保持稳定顺序
    order = {n: i for i, n in enumerate(ALL_SOURCES)}
    results.sort(key=lambda r: order.get(r["source"], 99))
    return aggregate(ip, results)


# --------------------------------------------------------------------------- #
# 报表渲染
# --------------------------------------------------------------------------- #
class C:
    def __init__(self, enabled=True):
        self.on = enabled

    def _w(self, code, s):
        return ("\033[%sm%s\033[0m" % (code, s)) if self.on else str(s)

    def b(self, s):
        return self._w("1", s)

    def dim(self, s):
        return self._w("2", s)

    def green(self, s):
        return self._w("32", s)

    def yellow(self, s):
        return self._w("33", s)

    def orange(self, s):
        return self._w("38;5;208", s)

    def red(self, s):
        return self._w("31", s)

    def cyan(self, s):
        return self._w("36", s)


def _fmt_bool(v):
    if v is True:
        return "是"
    if v is False:
        return "否"
    return "未知"


def _color_level(c, level, s):
    return {"clean": c.green, "low": c.yellow, "medium": c.orange, "high": c.red}.get(level, str)(s)


def render_report(agg, color=True):
    c = C(color)
    geo, net, fl, sc, vd = agg["geo"], agg["network"], agg["flags"], agg["scores"], agg["verdict"]
    lines = []
    lines.append(c.b("=" * 60))
    lines.append(c.b("IP 信誉检测报告  ") + c.cyan(agg["ip"]))
    lines.append(c.b("=" * 60))

    loc = " ".join([x for x in [geo.get("country"), geo.get("region"), geo.get("city")] if x]) or "-"
    lines.append("位置        : " + loc + (("   时区 " + geo["timezone"]) if geo.get("timezone") else ""))
    lines.append("ASN / 组织  : " + (net.get("asn_org") or "-"))
    lines.append("ISP         : " + (net.get("isp") or "-"))
    if net.get("hostname"):
        lines.append("PTR 主机名  : " + str(net["hostname"]))
    if net.get("type"):
        lines.append("网络类型    : " + str(net["type"]) + ((" / 用途:" + str(net["usage_type"])) if net.get("usage_type") else ""))
    lines.append("-" * 60)
    lines.append("代理 Proxy  : " + _fmt_bool(fl.get("proxy")) +
                 "    VPN: " + _fmt_bool(fl.get("vpn")) +
                 "    托管 Hosting: " + _fmt_bool(fl.get("hosting")))
    lines.append("移动网络    : " + _fmt_bool(fl.get("mobile")) + "    Tor: " + _fmt_bool(fl.get("tor")))
    extra = []
    if fl.get("residential_proxy") is not None:
        extra.append("住宅代理: " + _fmt_bool(fl.get("residential_proxy")))
    if sc.get("iphub_block") is not None:
        extra.append("iphub block: %s（0=住宅 / 1=坏 / 2=混合）" % sc.get("iphub_block"))
    if extra:
        lines.append("附加信号    : " + "    ".join(extra))
    lines.append("-" * 60)
    fs = sc.get("fraud_score")
    fr = sc.get("fraud_risk")
    lines.append("欺诈分(Scamalytics): " + (("%d/100" % fs) if fs is not None else "—") +
                 (("  (%s Risk)" % fr) if fr else ""))
    ac = sc.get("abuse_confidence")
    ar = sc.get("abuse_reports")
    lines.append("滥用置信度(AbuseIPDB): " + (("%d%%" % ac) if ac is not None else "—（需 ABUSEIPDB_API_KEY）") +
                 (("  报告数:%s" % ar) if ar is not None else ""))
    free = []
    if sc.get("sfs_frequency") is not None:
        free.append("StopForumSpam频率:%s" % sc.get("sfs_frequency"))
    if sc.get("bl_attacks") is not None:
        free.append("blocklist.de攻击:%s" % sc.get("bl_attacks"))
    if sc.get("ipsum_listed") is not None:
        free.append("IPsum:" + ("命中(%s条)" % sc.get("ipsum_score") if sc.get("ipsum_listed") else "未命中"))
    lines.append("滥用举报(免key)      : " + ("  ".join(free) if free else "—"))
    lines.append("-" * 60)
    verdict = "%d/100  %s" % (vd["risk_score"], vd["label"])
    lines.append("综合判定    : " + _color_level(c, vd["risk_level"], verdict))
    for note in agg.get("conflicts", []):
        lines.append(c.dim("备注        : " + note))
    lines.append("-" * 60)
    ok = [SOURCE_LABEL[r["source"]] for r in agg["sources"] if r["ok"]]
    bad = [SOURCE_LABEL[r["source"]] + "(" + (r["error"] or "失败") + ")"
           for r in agg["sources"] if not r["ok"]]
    lines.append("数据源 成功 : " + (", ".join(ok) if ok else "无"))
    if bad:
        lines.append("数据源 跳过 : " + ", ".join(bad))
    lines.append(c.b("=" * 60))
    return "\n".join(lines)


def render_brief(agg):
    """一行式简报，便于快速扫读。"""
    geo, net, fl, sc, vd = agg["geo"], agg["network"], agg["flags"], agg["scores"], agg["verdict"]
    loc = ",".join([x for x in [geo.get("country"), geo.get("city")] if x]) or "-"
    abuse = sc.get("abuse_confidence")
    fs = sc.get("fraud_score")
    flag = {"clean": "🟢", "low": "🟡", "medium": "🟠", "high": "🔴"}.get(vd["risk_level"], "")
    parts = [
        agg["ip"], loc, (net.get("asn_org") or "-"),
        "proxy:%s vpn:%s host:%s" % (_fmt_bool(fl.get("proxy")), _fmt_bool(fl.get("vpn")), _fmt_bool(fl.get("hosting"))),
        "fraud:%s" % (fs if fs is not None else "-"),
        "abuse:%s" % ((str(abuse) + "%") if abuse is not None else "-"),
        "ipsum:%s" % ("命中" if sc.get("ipsum_listed") else ("未" if sc.get("ipsum_listed") is not None else "-")),
        "%s %d/100" % (flag, vd["risk_score"]),
    ]
    return " | ".join(parts)


def render_json(agg):
    return json.dumps(agg, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------- #
# 出口 IP / 稳定性
# --------------------------------------------------------------------------- #
EGRESS_ENDPOINTS = [
    ("https://icanhazip.com", None),
    ("https://ifconfig.me/ip", None),
    ("https://ipinfo.io/ip", None),
    ("https://api.ipify.org", None),
    ("https://ipv4.icanhazip.com", None),
]


def get_egress_ip(timeout=DEFAULT_TIMEOUT):
    """返回 (ip, source_url)；收集多源，取众数。"""
    seen = {}
    for url, _ in EGRESS_ENDPOINTS:
        try:
            _, txt = http_get(url, timeout=timeout, retries=0)
            ip = txt.strip().splitlines()[0].strip()
            if re.match(r"^[0-9a-fA-F:.]+$", ip):
                seen.setdefault(ip, []).append(url)
        except Exception:
            continue
    if not seen:
        return None, None
    # 众数
    best = max(seen.items(), key=lambda kv: len(kv[1]))
    return best[0], best[1][0]


def cmd_myip(args):
    ip, via = get_egress_ip(args.timeout)
    if not ip:
        print("无法获取出口 IP（所有回显源均失败）")
        return 2
    if args.json:
        print(json.dumps({"egress_ip": ip, "via": via}, ensure_ascii=False, indent=2))
    else:
        print("当前出口 IP: " + ip + "   (来源: " + str(via) + ")")
    return 0


def cmd_open(args):
    """一键打开网页并自动带上 IP（用于人工核验被 Cloudflare 拦的站点）。"""
    import webbrowser
    from ipaddress import ip_address
    try:
        ip_address(args.ip)
    except ValueError:
        print("非法 IP: " + args.ip, file=sys.stderr)
        return 2
    urls = {
        "abuseipdb": "https://www.abuseipdb.com/check/%s" % args.ip,
        "iphub": "https://iphub.info/?ip=%s" % args.ip,
        "scamalytics": "https://scamalytics.com/ip/%s" % args.ip,
        "stopforumspam": "https://www.stopforumspam.com/search?q=%s" % args.ip,
    }
    if args.all:
        which = list(urls)
    elif args.which:
        which = [x.strip() for x in args.which.split(",") if x.strip()]
        bad = [x for x in which if x not in urls]
        if bad:
            print("未知站点: %s（可选: %s）" % (",".join(bad), ",".join(urls)), file=sys.stderr)
            return 2
    else:
        which = ["abuseipdb"]
    for name in which:
        u = urls[name]
        print("打开 %-14s %s" % (name, u))
        try:
            webbrowser.open(u)
        except Exception as e:  # noqa: BLE001
            print("  打不开浏览器，请手动访问上面的链接（%s）" % e, file=sys.stderr)
    return 0


def cmd_stability(args):
    color = not args.no_color and sys.stdout.isatty()
    c = C(color)

    if args.interactive:
        print(c.b("[第 1 步] 采样当前出口 IP ..."))
        ip1, via1 = get_egress_ip(args.timeout)
        if not ip1:
            print("无法获取出口 IP"); return 2
        print("  当前出口 IP: " + c.cyan(ip1) + "  (来源 " + str(via1) + ")")
        print("\n现在请执行：断开当前网络 / 切换节点 / 重连代理，然后回到这里。")
        try:
            input("完成后按回车继续 ...")
        except EOFError:
            pass
        print(c.b("\n[第 2 步] 重连后再次采样 ..."))
        ip2, via2 = get_egress_ip(args.timeout)
        if not ip2:
            print("无法获取出口 IP"); return 2
        print("  重连后 IP: " + c.cyan(ip2) + "  (来源 " + str(via2) + ")")

        stable = (ip1 == ip2)
        print("-" * 60)
        if stable:
            print(c.green("稳定性结论: 稳定 —— 断开重连前后出口 IP 一致 (%s)" % ip1))
        else:
            print(c.yellow("稳定性结论: 已变更 —— %s  ->  %s" % (ip1, ip2)))
        print("-" * 60)
        print(c.b("\n对重连后的 IP 做完整信誉检测："))
        agg = check_ip(ip2, only=args.only, timeout=args.timeout)
        print(render_report(agg, color=color))
        if args.json:
            print(render_json(agg))
        return 0

    # 非交互：连续采样
    ips = []
    print(c.b("连续采样出口 IP：%d 轮，间隔 %ds" % (args.rounds, args.interval)))
    for i in range(args.rounds):
        ip, via = get_egress_ip(args.timeout)
        ts = time.strftime("%H:%M:%S")
        if ip:
            ips.append(ip)
            print("  [%s] #%d  %s" % (ts, i + 1, ip))
        else:
            print("  [%s] #%d  采样失败" % (ts, i + 1))
        if i < args.rounds - 1:
            time.sleep(args.interval)
    uniq = sorted(set(ips))
    print("-" * 60)
    if len(uniq) == 1:
        print(c.green("稳定性结论: 稳定 —— 全部 %d 次采样均为 %s" % (len(ips), uniq[0])))
    elif len(uniq) == 0:
        print(c.red("稳定性结论: 全部采样失败"))
    else:
        print(c.yellow("稳定性结论: 漂移 —— 出现 %d 个不同出口 IP: %s" % (len(uniq), ", ".join(uniq))))
    if args.json:
        print(json.dumps({"samples": ips, "unique": uniq}, ensure_ascii=False, indent=2))
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _parse_only(s):
    if not s:
        return None
    names = [x.strip() for x in re.split(r"[,\s]+", s) if x.strip()]
    bad = [n for n in names if n not in SOURCES]
    if bad:
        raise argparse.ArgumentTypeError("未知数据源: %s（可选: %s）"
                                         % (",".join(bad), ",".join(ALL_SOURCES)))
    return names


def gateway_check(ip, base, token=None, timeout=30):
    """通过自建网关查询（客户端无需任何源 key）。"""
    url = base.rstrip("/") + "/check?ip=" + urllib.parse.quote(ip)
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    status, txt = http_get(url, headers=headers, timeout=timeout, retries=0)
    return _j(txt)


def cmd_check(args):
    color = not args.no_color and sys.stdout.isatty()
    from ipaddress import ip_address
    gw = (args.gateway or os.environ.get("IPCHECK_GATEWAY", "").strip() or None)
    gw_token = os.environ.get("IPCHECK_GATEWAY_TOKEN", "").strip() or None
    rc = 0
    for idx, ip in enumerate(args.ips):
        try:
            ip_address(ip)
        except ValueError:
            print("跳过非法 IP: " + ip, file=sys.stderr)
            rc = 2
            continue
        if gw:
            try:
                agg = gateway_check(ip, gw, gw_token, timeout=max(args.timeout, 30))
            except Exception as e:  # noqa: BLE001
                print("网关查询失败(%s): %s" % (gw, e), file=sys.stderr)
                rc = 2
                continue
        else:
            agg = check_ip(ip, only=args.only, timeout=args.timeout)
        if args.json:
            print(render_json(agg))
        elif getattr(args, "brief", False):
            print(render_brief(agg))
        else:
            if idx:
                print()
            print(render_report(agg, color=color))
        if getattr(args, "open", False):
            import webbrowser
            for u in ("https://www.abuseipdb.com/check/%s" % ip,
                      "https://iphub.info/?ip=%s" % ip):
                try:
                    webbrowser.open(u)
                except Exception:
                    pass
            print("已打开 abuseipdb / iphub 网页（IP 已带入，可人工核验）")
    return rc


def build_parser():
    p = argparse.ArgumentParser(
        prog="ipcheck",
        description="多源 IP 信誉检测（ipinfo / ip-api / ipwho.is / proxycheck / scamalytics / iphub / abuseipdb）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  ipcheck check 8.8.8.8\n"
               "  ipcheck 8.8.8.8 --brief\n"
               "  ipcheck 8.8.8.8 --open          # 同时打开 abuseipdb/iphub 网页(带IP)\n"
               "  ipcheck open 8.8.8.8 --all      # 只打开网页人工核验\n"
               "  ipcheck myip\n"
               "  ipcheck stability --rounds 5 --interval 3\n"
               "  ipcheck stability --interactive\n")
    sub = p.add_subparsers(dest="cmd")

    pc = sub.add_parser("check", help="检测一个或多个 IP")
    pc.add_argument("ips", nargs="+", help="要检测的 IP（可多个）")
    pc.add_argument("--only", type=_parse_only, default=None,
                    help="只用这些源，逗号分隔: " + ",".join(ALL_SOURCES))
    pc.add_argument("--json", action="store_true", help="输出 JSON")
    pc.add_argument("--brief", action="store_true", help="一行式简报")
    pc.add_argument("--open", action="store_true", help="检测后自动打开 abuseipdb/iphub 网页(IP已带入)")
    pc.add_argument("--gateway", default=None,
                    help="走自建网关（也可用环境变量 IPCHECK_GATEWAY），客户端无需任何源 key")
    pc.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    pc.add_argument("--no-color", action="store_true")
    pc.set_defaults(func=cmd_check)

    po = sub.add_parser("open", help="打开网页并自动填入 IP（人工核验用）")
    po.add_argument("ip")
    po.add_argument("--all", action="store_true", help="打开全部站点")
    po.add_argument("--which", default=None,
                    help="指定站点，逗号分隔: abuseipdb,iphub,scamalytics,stopforumspam")
    po.set_defaults(func=cmd_open)

    pm = sub.add_parser("myip", help="查看当前出口 IP")
    pm.add_argument("--json", action="store_true")
    pm.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    pm.add_argument("--no-color", action="store_true")
    pm.set_defaults(func=cmd_myip)

    ps = sub.add_parser("stability", help="出口 IP 稳定性检测")
    ps.add_argument("--rounds", type=int, default=3, help="采样轮数（非交互）")
    ps.add_argument("--interval", type=int, default=5, help="采样间隔秒（非交互）")
    ps.add_argument("--interactive", action="store_true", help="断开/重连前后对比")
    ps.add_argument("--only", type=_parse_only, default=None, help="完整检测时使用的源")
    ps.add_argument("--json", action="store_true")
    ps.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ps.add_argument("--no-color", action="store_true")
    ps.set_defaults(func=cmd_stability)
    return p


def main(argv=None):
    _setup_console()
    argv = argv if argv is not None else sys.argv[1:]
    # 简化：允许直接 `ipcheck.py 8.8.8.8`（等价于 check）
    if argv and argv[0] not in ("check", "myip", "stability", "open", "-h", "--help") and not argv[0].startswith("-"):
        argv = ["check"] + argv
    p = build_parser()
    if not argv:
        p.print_help()
        return 0
    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        p.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n已中断", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
