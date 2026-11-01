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
               "iphub", "abuseipdb", "stopforumspam", "blocklistde", "ipsum",
               "spamhaus", "virustotal", "dbip", "maxmind"]

# 云/机房组织关键字（辅助判断 hosting）
CLOUD_HINTS = ("amazon", "aws", "google", "microsoft", "azure", "digitalocean",
               "linode", "akamai", "cloudflare", "ovh", "hetzner", "vultr",
               "alibaba", "aliyun", "tencent", "oracle", "gcore", "leaseweb",
               "choopa", "contabo", "hosting", "datacenter", "data center",
               "server", "colo")

# 平台适配度：各信号对不同平台类别的风险权重（启发式，非平台真实判定）
PLATFORM_PROFILES = {
    "社交媒体(X/FB/IG/TikTok)": {"hosting": 45, "proxy": 45, "vpn": 45, "tor": 85,
                               "mobile": -20, "abuse": 30},
    "AI工具(OpenAI/Claude/Gemini)": {"hosting": 55, "proxy": 55, "vpn": 55, "tor": 85,
                                    "mobile": -10, "abuse": 30, "country_restricted": 95},
    "电商/支付(Amazon/PayPal)": {"hosting": 60, "proxy": 60, "vpn": 60, "tor": 90,
                              "mobile": -10, "abuse": 40},
    "流媒体(Netflix/Spotify)": {"hosting": 40, "proxy": 35, "vpn": 40, "tor": 80,
                             "mobile": -15, "abuse": 20},
    "注册/论坛/爬虫": {"hosting": 45, "proxy": 50, "vpn": 50, "tor": 85,
                   "mobile": -15, "abuse": 35},
}
# 常被主流 AI 服务限制的国家/地区（以平台最新政策为准，仅作提示）
AI_RESTRICTED = {"CN", "RU", "IR", "KP", "SY", "CU", "BY", "VE", "MM"}

# 具体平台规则库（cat=所属类别，strict=该类基线风险的放大系数，note=风控特点）
PLATFORMS = {
    "X (Twitter)": {"cat": "社交媒体(X/FB/IG/TikTok)", "strict": 1.05, "note": "机房/VPN 易触发手机号验证或封号"},
    "Facebook/Instagram": {"cat": "社交媒体(X/FB/IG/TikTok)", "strict": 1.15, "note": "新号+机房IP 极易封，需养号"},
    "TikTok": {"cat": "社交媒体(X/FB/IG/TikTok)", "strict": 1.2, "note": "强地区限制，需目标区住宅/移动IP"},
    "Telegram": {"cat": "社交媒体(X/FB/IG/TikTok)", "strict": 0.55, "note": "对 VPN/代理较宽松"},
    "WhatsApp": {"cat": "社交媒体(X/FB/IG/TikTok)", "strict": 0.8, "note": "需手机号，IP 敏感度中等"},
    "Google/Gmail": {"cat": "注册/论坛/爬虫", "strict": 1.1, "note": "机房IP注册常要手机验证"},
    "OpenAI/ChatGPT": {"cat": "AI工具(OpenAI/Claude/Gemini)", "strict": 1.1, "note": "杀机房 + 地区限制"},
    "Claude": {"cat": "AI工具(OpenAI/Claude/Gemini)", "strict": 1.1, "note": "杀机房 + 地区限制"},
    "Gemini": {"cat": "AI工具(OpenAI/Claude/Gemini)", "strict": 0.9, "note": "机房较敏感"},
    "Midjourney": {"cat": "AI工具(OpenAI/Claude/Gemini)", "strict": 0.8, "note": "走 Discord，IP 敏感度中"},
    "Amazon": {"cat": "电商/支付(Amazon/PayPal)", "strict": 1.15, "note": "新号+代理IP 高风险"},
    "PayPal": {"cat": "电商/支付(Amazon/PayPal)", "strict": 1.25, "note": "风控最严，机房/代理基本不可用"},
    "Binance/交易所": {"cat": "电商/支付(Amazon/PayPal)", "strict": 1.3, "note": "KYC + 地区 + 设备风控极严"},
    "Netflix": {"cat": "流媒体(Netflix/Spotify)", "strict": 1.0, "note": "封 VPN，需原生住宅"},
    "Spotify": {"cat": "流媒体(Netflix/Spotify)", "strict": 0.65, "note": "地区限制为主"},
}

# 服务地区可用性（按 IP 所在国判断；近似值，以各平台官方最新政策为准）
SERVICE_REGIONS = {
    "OpenAI/ChatGPT": {"restricted": set(AI_RESTRICTED) | {"SD", "SS", "AF"}, "note": "需支持地区 + 非机房"},
    "Claude": {"restricted": set(AI_RESTRICTED) | {"SD", "SS"}, "note": "需支持地区"},
    "Gemini": {"restricted": {"CN", "RU", "KP", "IR", "SY", "CU"}, "note": ""},
    "Netflix": {"restricted": {"CN", "KP", "SY", "IR", "RU"}, "note": "地区内容不同，封VPN"},
    "Spotify": {"restricted": {"CN", "KP", "IR", "SY"}, "note": ""},
    "TikTok": {"restricted": {"CN", "IR", "KP", "IN", "SY"}, "note": "部分地区禁用"},
    "PayPal": {"restricted": {"IR", "KP", "SY", "CU", "SD", "SS"}, "note": ""},
    "Binance": {"restricted": {"US", "CN", "IR", "KP", "SY", "CU"}, "note": "美国需 binance.us"},
    "Steam": {"restricted": {"KP", "IR", "SY", "CU"}, "note": ""},
}


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
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(min(timeout, 8))
        ans = socket.gethostbyname(rev)
    except socket.gaierror:
        return {"listed": False, "zones": [], "answer": None}
    finally:
        socket.setdefaulttimeout(old)
    if ans.startswith("127.255.255."):
        raise RuntimeError("Spamhaus 拒绝当前 DNS 出口（公共解析器/超量），请直连或降低频率")
    code_map = {
        "127.0.0.2": "SBL", "127.0.0.3": "XBL/CSS", "127.0.0.4": "PBL",
        "127.0.0.5": "PBL", "127.0.0.6": "PBL", "127.0.0.7": "PBL",
        "127.0.0.9": "DROP", "127.0.0.10": "PBL", "127.0.0.11": "PBL",
    }
    zones = [code_map[ans]] if ans in code_map else []
    listed = ans.startswith("127.0.0.")
    return {"listed": listed, "zones": zones, "answer": ans}


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

SOURCE_LABEL = {
    "ipinfo": "ipinfo.io", "ipapi": "ip-api.com", "ipwhois": "ipwho.is",
    "proxycheck": "proxycheck.io", "scamalytics": "scamalytics.com",
    "iphub": "iphub.info", "abuseipdb": "abuseipdb.com",
    "stopforumspam": "stopforumspam.com", "blocklistde": "blocklist.de",
    "ipsum": "IPsum(聚合黑名单)", "spamhaus": "Spamhaus DNSBL",
    "virustotal": "VirusTotal", "dbip": "DB-IP", "maxmind": "MaxMind GeoLite2",
}

# 源等级：A=权威/商业数据源，B=专业检测，C=社区/聚合（仅供参考）
SOURCE_TIER = {
    "ipinfo": "A", "spamhaus": "A", "virustotal": "A", "maxmind": "A", "dbip": "A",
    "ipapi": "B", "proxycheck": "B", "blocklistde": "B",
    "ipwhois": "C", "iphub": "C", "scamalytics": "C",
    "abuseipdb": "C", "stopforumspam": "C", "ipsum": "C",
}
TIER_WEIGHT = {"A": 3, "B": 2, "C": 1}


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
    order = ["maxmind", "ipapi", "dbip", "ipinfo", "ipwhois", "proxycheck"]
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


def _conf_bool(votes):
    """布尔型结论的置信度：按源等级加权求一致度。"""
    known = [(s, v) for s, v in votes if v is not None]
    if not known:
        return {"level": "unknown", "n": 0}
    tw = sum(TIER_WEIGHT.get(SOURCE_TIER.get(s, "C"), 1) for s, _ in known)
    tw_true = sum(TIER_WEIGHT.get(SOURCE_TIER.get(s, "C"), 1) for s, v in known if v)
    maj = max(tw_true, tw - tw_true)
    ratio = (maj / tw) if tw else 0
    n = len(known)
    if n >= 2 and ratio >= 0.75:
        lvl = "high"
    elif n >= 2 and ratio >= 0.6:
        lvl = "medium"
    else:
        lvl = "low"
    tw_false = tw - tw_true
    if tw_true == tw_false:
        val = known[0][1]          # 平票取优先源（votes 已按可信度排序）
    else:
        val = tw_true > tw_false
    return {"level": lvl, "n": n, "value": val}


def _conf_cat(votes):
    """类别型结论（如国家）的置信度：按源等级加权求众数占比。"""
    known = [(s, str(v).upper()) for s, v in votes if v]
    if not known:
        return {"level": "unknown", "n": 0}
    weights = {}
    for s, v in known:
        weights[v] = weights.get(v, 0) + TIER_WEIGHT.get(SOURCE_TIER.get(s, "C"), 1)
    total = sum(weights.values())
    val, top = max(weights.items(), key=lambda kv: kv[1])
    ratio = (top / total) if total else 0
    n = len(known)
    if n >= 2 and ratio >= 0.75:
        lvl = "high"
    elif n >= 2 and ratio >= 0.6:
        lvl = "medium"
    else:
        lvl = "low"
    return {"level": lvl, "n": n, "value": val}


def _platform_level(score):
    if score < 25:
        return "low", "🟢 适用"
    if score < 55:
        return "medium", "🟡 谨慎"
    return "high", "🔴 易被风控"


def _platform_fit(flags, geo, net, scores):
    """基于 IP 画像给各平台类别的「可用度风险」启发式评分。"""
    abuse_hit = bool(scores.get("spamhaus_listed")) or \
        (scores.get("vt_malicious") or 0) > 0 or \
        (scores.get("abuse_confidence") or 0) >= 25 or bool(scores.get("ipsum_listed"))
    cc = (geo.get("country_code") or "").upper()
    asn_low = (net.get("asn_org") or "").lower()
    hosting = flags.get("hosting") if flags.get("hosting") is not None else any(k in asn_low for k in CLOUD_HINTS)
    out = []
    for cat, w in PLATFORM_PROFILES.items():
        score = 0
        reasons = []
        if hosting:
            score += w.get("hosting", 0); reasons.append("机房/托管")
        if flags.get("proxy"):
            score += w.get("proxy", 0); reasons.append("代理")
        if flags.get("vpn"):
            score += w.get("vpn", 0); reasons.append("VPN")
        if flags.get("tor"):
            score += w.get("tor", 0); reasons.append("Tor")
        if flags.get("mobile"):
            score += w.get("mobile", 0); reasons.append("移动网络(较优)")
        if abuse_hit:
            score += w.get("abuse", 0); reasons.append("有滥用记录")
        if "AI" in cat and cc in AI_RESTRICTED:
            score += w.get("country_restricted", 0); reasons.append("所在国可能不在支持地区(%s)" % cc)
        score = max(0, min(100, score))
        lvl, label = _platform_level(score)
        if not reasons:
            reasons.append("住宅/普通网络，风险低")
        out.append({"category": cat, "score": score, "level": lvl,
                    "label": label, "reason": ", ".join(reasons)})
    return out


DECISION_LABEL = {"ok": "✅ 推荐", "warn": "⚠️ 谨慎", "no": "⛔ 不建议"}


def _abuse_hit(scores):
    return bool(scores.get("spamhaus_listed")) or \
        (scores.get("vt_malicious") or 0) > 0 or \
        (scores.get("abuse_confidence") or 0) >= 25 or bool(scores.get("ipsum_listed"))


def compute_decisions(ip_type, flags, scores, geo):
    """把信号收敛成「能不能注册 / 养号 / 爬 / 支付 / 流媒体」的可执行建议。"""
    t = ip_type or ""
    datacenter = "机房" in t
    vpn = "VPN" in t
    proxy = "代理" in t
    tor = "Tor" in t
    mobile = "移动" in t
    residential = ("住宅" in t) and not (vpn or proxy or tor)
    abuse = _abuse_hit(scores)
    anon = vpn or proxy or tor
    out = []

    def add(use, lvl, reason):
        out.append({"use": use, "level": lvl, "label": DECISION_LABEL[lvl], "reason": reason})

    # 注册社媒/AI
    if anon:
        add("注册社媒/AI 账号", "no", "代理/VPN/Tor IP 极易被判异常、要求验证或封号")
    elif datacenter:
        add("注册社媒/AI 账号", "warn", "机房 IP 易触发手机验证；AI 常直接拦机房")
    elif residential or mobile:
        add("注册社媒/AI 账号", "warn" if abuse else "ok",
            "住宅/移动 IP 但存在滥用记录" if abuse else "住宅/移动 IP，较像真人，成功率较高")
    else:
        add("注册社媒/AI 账号", "warn", "类型不确定，建议先用浏览器环境实测")

    # 长期养号
    if (residential or mobile) and not abuse:
        add("长期养号", "ok", "住宅/移动 IP + 无滥用，适合养号（务必保持出口稳定）")
    elif datacenter or anon:
        add("长期养号", "no", "机房/代理/VPN IP 不利于长期养号，易被清理")
    else:
        add("长期养号", "warn", "存在风险信号，养号需谨慎")

    # 爬虫/采集
    if datacenter and not abuse:
        add("爬虫/数据采集", "ok", "机房 IP 适合高并发采集（注意目标站反爬）")
    elif abuse:
        add("爬虫/数据采集", "warn", "有滥用记录，部分站点会直接封")
    else:
        add("爬虫/数据采集", "warn", "可用，但住宅 IP 做采集成本高/易触发")

    # 电商/支付
    if datacenter or anon or abuse:
        add("电商/支付", "no", "风控最严，机房/代理/滥用 IP 基本不可用")
    else:
        add("电商/支付", "warn", "住宅 IP 可试，但支付类仍需 KYC 与行为验证")

    # 流媒体
    if vpn:
        add("流媒体解锁", "warn", "VPN 可能被封（Netflix 等），需实测")
    elif datacenter:
        add("流媒体解锁", "warn", "机房 IP 多数流媒体会拦，原生住宅更稳")
    else:
        add("流媒体解锁", "ok", "住宅/原生 IP 解锁成功率较高")
    return out


def compute_platforms(flags, geo, net, scores):
    """按具体平台给可用度（基于平台规则库 × 类别基线分）。"""
    cat_scores = {item["category"]: item["score"] for item in _platform_fit(flags, geo, net, scores)}
    cc = (geo.get("country_code") or "").upper()
    out = []
    for name, cfg in PLATFORMS.items():
        base = cat_scores.get(cfg["cat"], 0)
        score = min(100, round(base * cfg.get("strict", 1.0)))
        if cfg["cat"].startswith("AI") and cc in AI_RESTRICTED:
            score = max(score, 90)
        lvl, label = _platform_level(score)
        out.append({"platform": name, "score": score, "level": lvl, "label": label,
                    "note": cfg.get("note", "")})
    return out


def render_platforms(agg):
    rows = agg.get("platforms") or []
    if not rows:
        return ""
    lines = ["各平台可用度(启发式,非平台真实判定):"]
    for r in rows:
        lines.append("  %s  %-18s %s" % (r["label"], r["platform"], r["note"]))
    return "\n".join(lines)


def compute_regions(geo):
    """按 IP 所在国判断各服务是否可用（近似，以官方为准）。"""
    cc = (geo.get("country_code") or "").upper()
    name = geo.get("country") or cc or "?"
    out = []
    for svc, cfg in SERVICE_REGIONS.items():
        restricted = cc in cfg.get("restricted", set())
        out.append({
            "service": svc,
            "available": not restricted,
            "label": "⛔ 受限/不可用" if restricted else "✅ 可用(约)",
            "note": cfg.get("note", ""),
        })
    return {"country": name, "country_code": cc, "services": out}


def render_regions(reg):
    lines = ["服务地区可用性(按 IP 所在国 %s，近似，以官方为准):" % (reg.get("country") or "?"), ]
    for s in reg.get("services", []):
        lines.append("  %s  %-16s %s" % (s["label"], s["service"], s["note"]))
    return "\n".join(lines)


def write_csv(rows, path):
    """把检测结果导出 CSV（UTF-8-BOM，Excel 可直接打开）。"""
    import csv
    cols = ["ip", "country", "city", "asn_org", "ip_type", "proxy", "vpn", "hosting",
            "mobile", "fraud_score", "abuse_confidence", "spamhaus", "vt_malicious",
            "risk_score", "risk_level", "geo_conf", "proxy_conf", "abuse_conf"]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in rows:
            w.writerow([r.get(c, "") for c in cols])
    return path


def _agg_to_row(agg):
    geo, net, fl, sc, vd = agg["geo"], agg["network"], agg["flags"], agg["scores"], agg["verdict"]
    conf = agg.get("confidence") or {}
    return {
        "ip": agg.get("ip"), "country": geo.get("country"), "city": geo.get("city"),
        "asn_org": net.get("asn_org"), "ip_type": agg.get("ip_type"),
        "proxy": fl.get("proxy"), "vpn": fl.get("vpn"), "hosting": fl.get("hosting"),
        "mobile": fl.get("mobile"), "fraud_score": sc.get("fraud_score"),
        "abuse_confidence": sc.get("abuse_confidence"), "spamhaus": sc.get("spamhaus_listed"),
        "vt_malicious": sc.get("vt_malicious"), "risk_score": vd.get("risk_score"),
        "risk_level": vd.get("risk_level"),
        "geo_conf": (conf.get("geo") or {}).get("level"),
        "proxy_conf": (conf.get("proxy") or {}).get("level"),
        "abuse_conf": (conf.get("abuse") or {}).get("level"),
    }


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
    maxmind, dbip = srcs["maxmind"], srcs["dbip"]

    geo = _coherent_geo(srcs)
    asn_org = _pick(ipinfo.get("asn_org"), maxmind.get("asn_org"), ipapi.get("asn_org"),
                    ipwho.get("org"),
                    (("AS%s " % ipwho.get("asn")) if ipwho.get("asn") else None),
                    proxycheck.get("asn"))
    isp = _pick(ipapi.get("isp"), ipwho.get("isp"), proxycheck.get("provider"), iphub.get("isp"))
    hostname = _pick(ipapi.get("hostname"), ipinfo.get("hostname"))

    conflicts = []
    # 代理：优先专用代理库 proxycheck，其次 iphub，最后 ip-api
    proxy_votes = [
        ("proxycheck", proxycheck.get("proxy")),
        ("iphub", iphub.get("proxy")),
        ("ipapi", ipapi.get("proxy")),
    ]
    proxy = _vote(conflicts, "Proxy", proxy_votes)
    # VPN
    vpn_votes = [
        ("proxycheck", proxycheck.get("vpn")),
        ("iphub", (True if iphub.get("block") in (1,) else None)),
    ]
    vpn = _vote(conflicts, "VPN", vpn_votes)
    # 托管：ip-api 的 hosting 最直接，其次 proxycheck 类型，最后按组织关键字推断
    hosting_votes = [
        ("ipapi", ipapi.get("hosting")),
        ("proxycheck", proxycheck.get("hosting")),
        ("iphub", iphub.get("hosting")),
        ("ipinfo", _hosting_from_org(asn_org or isp)),
    ]
    hosting = _vote(conflicts, "Hosting", hosting_votes)
    mobile = ipapi.get("mobile") if ipapi.get("mobile") is not None else None
    tor = _pick_bool(abuse.get("is_tor"), iphub.get("tor"))
    ip_type = classify_ip_type(
        {"tor": tor, "vpn": vpn, "proxy": proxy, "hosting": hosting, "mobile": mobile},
        {"type": proxycheck.get("type")}, asn_org)

    fraud_score = _to_int(scam.get("fraud_score"))
    fraud_risk = scam.get("risk")
    abuse_conf = _to_int(abuse.get("abuse_confidence"))

    spamhaus, vt = srcs["spamhaus"], srcs["virustotal"]
    spamhaus_listed = bool(spamhaus.get("listed"))
    vt_mal = _to_int(vt.get("malicious"))

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

    # 权威滥用信号并入风险（Spamhaus / VirusTotal 权重最高）
    cands = []
    if abuse_conf is not None:
        cands.append(abuse_conf)
    if spamhaus_listed:
        cands.append(90)
    if vt_mal:
        cands.append(min(100, 30 + vt_mal * 10))
    abuse_for_risk = max(cands) if cands else None

    risk_score, risk_level = compute_risk(fraud_score, abuse_for_risk, proxy, vpn, hosting,
                                           tor, mobile, free_pts)

    # 置信度：源等级 × 多源一致度
    geo_votes = [
        ("maxmind", srcs["maxmind"].get("country_code")),
        ("dbip", srcs["dbip"].get("country_code")),
        ("ipinfo", ipinfo.get("country")),
        ("ipapi", ipapi.get("country_code")),
        ("ipwhois", ipwho.get("country_code")),
        ("proxycheck", proxycheck.get("country_code")),
    ]
    if spamhaus_listed or (vt_mal and vt_mal > 0):
        conf_abuse = {"level": "high", "note": "权威源命中"}
    elif (abuse_conf and abuse_conf > 0) or (sfs_freq and sfs_freq > 0) or \
            (bl_attacks and bl_attacks > 0) or ipsum_listed:
        conf_abuse = {"level": "medium", "note": "仅社区/聚合命中"}
    else:
        conf_abuse = {"level": "low", "note": "无命中≠安全"}
    confidence = {
        "geo": _conf_cat(geo_votes),
        "proxy": _conf_bool(proxy_votes),
        "vpn": _conf_bool(vpn_votes),
        "hosting": _conf_bool(hosting_votes),
        "abuse": conf_abuse,
    }

    flags_view = {"proxy": proxy, "vpn": vpn, "hosting": hosting, "mobile": mobile, "tor": tor}
    scores_view = {"spamhaus_listed": spamhaus_listed, "vt_malicious": vt_mal,
                   "abuse_confidence": abuse_conf, "ipsum_listed": ipsum_listed}
    net_view = {"asn_org": asn_org}
    platform_fit = _platform_fit(flags_view, geo, net_view, scores_view)
    decisions = compute_decisions(ip_type, flags_view, scores_view, geo)
    platforms = compute_platforms(flags_view, geo, net_view, scores_view)

    return {
        "ip": ip,
        "ip_type": ip_type,
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
                   "ipsum_listed": ipsum_listed, "ipsum_score": ipsum_score,
                   "spamhaus_listed": spamhaus_listed, "spamhaus_zones": spamhaus.get("zones"),
                   "vt_malicious": vt_mal, "vt_reputation": vt.get("reputation")},
        "verdict": {"risk_score": risk_score, "risk_level": risk_level,
                    "label": risk_label(risk_level)},
        "confidence": confidence,
        "platform_fit": platform_fit,
        "platforms": platforms,
        "decisions": decisions,
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


def classify_ip_type(flags, net, asn_org):
    """把 IP 归类为住宅/移动/机房/企业/教育/政府/Tor/VPN/代理。"""
    org = (asn_org or "").lower()
    ptype = (net.get("type") or "").lower()
    if flags.get("tor"):
        return "Tor 出口"
    if flags.get("vpn"):
        return "VPN"
    if flags.get("proxy"):
        return "代理/公共代理"
    if flags.get("hosting") or ptype in ("hosting", "datacenter") or any(k in org for k in CLOUD_HINTS):
        return "机房/云主机"
    if flags.get("mobile") or any(k in org for k in ("mobile", "wireless", "cellular", "4g", "5g", "lte", "蜂窝")):
        return "移动网络(4G/5G)"
    if any(k in org for k in ("university", "college", "school", "academy", "institute", "教育")):
        return "教育网"
    if any(k in org for k in ("government", "ministry", "gov", "municipal", "council", "政府")):
        return "政府/机构"
    if ptype == "business" or any(k in org for k in ("bank", "corp", "enterprise", "business", "company")):
        return "企业网络"
    if ptype in ("residential", "isp"):
        return "住宅/ISP"
    return "住宅/普通ISP（推断）"


def _local_utc_offset():
    import datetime
    return datetime.datetime.now().astimezone().utcoffset().total_seconds() / 3600.0


def get_dns_resolver(timeout=DEFAULT_TIMEOUT):
    """通过 edns.ip-api.com 拿当前 DNS 解析器出口（用于 DNS 泄漏判断）。"""
    try:
        _, txt = http_get("https://edns.ip-api.com/json", timeout=timeout, retries=0)
        d = _j(txt).get("dns", {}) or {}
        return {"ip": d.get("ip"), "geo": d.get("geo")}
    except Exception as e:  # noqa: BLE001
        return {"ip": None, "geo": None, "error": str(e)}


def env_consistency(geo, do_dns=True):
    """环境一致性：本机时区 vs IP 时区、DNS 出口国家 vs IP 国家（防关联指纹）。"""
    notes = []
    warn = False
    offset_local = _local_utc_offset()
    lon = geo.get("lon")
    ip_off = None
    tz_ok = None
    if lon is not None:
        try:
            ip_off = round(float(lon) / 15.0)
        except (TypeError, ValueError):
            ip_off = None
    if ip_off is not None:
        diff = abs(offset_local - ip_off)
        tz_ok = diff < 2
        if not tz_ok:
            warn = True
            notes.append("时区不一致：本机 UTC%+g vs IP≈UTC%+g（差 %g 小时）→ 浏览器时区指纹会穿帮" % (offset_local, ip_off, diff))
    dns = {}
    if do_dns:
        dns = get_dns_resolver()
        dgeo = dns.get("geo") or ""
        ipc = geo.get("country") or ""
        dns_country = dgeo.split(" - ")[0].strip() if dgeo else None
        if dns_country and ipc:
            dns_ok = (ipc.lower() in dgeo.lower()) or (dns_country.lower() in ipc.lower())
            if not dns_ok:
                warn = True
                notes.append("DNS 出口与 IP 国家不一致：DNS=%s，IP=%s → 可能 DNS 泄漏/未走代理" % (dns_country, ipc))
    return {"local_utc": offset_local, "ip_utc": ip_off, "tz_ok": tz_ok,
            "dns": dns, "warn": warn, "notes": notes}


def render_env(env):
    lines = []
    tz = env.get("tz_ok")
    if tz is None:
        tz_s = "无法判断"
    else:
        tz_s = "✅ 一致" if tz else "⚠️ 不一致"
    lines.append("环境一致性:")
    lines.append("  时区: 本机 UTC%+g  vs  IP≈UTC%s  %s" %
                 (env.get("local_utc", 0),
                  ("%+g" % env["ip_utc"]) if env.get("ip_utc") is not None else "?", tz_s))
    dns = env.get("dns") or {}
    if dns.get("geo"):
        lines.append("  DNS : 解析器 %s (%s)" % (dns.get("geo"), dns.get("ip")))
    elif dns.get("error"):
        lines.append("  DNS : 检测失败（%s）" % dns.get("error"))
    for n in env.get("notes", []):
        lines.append("  ⚠️ " + n)
    if not env.get("warn"):
        lines.append("  结论: ✅ 环境基本一致")
    else:
        lines.append("  结论: ⚠️ 环境不一致，易被平台风控识别")
    return "\n".join(lines)


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
    lines.append("IP 类型     : " + (agg.get("ip_type") or "-"))
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
    auth = []
    if sc.get("spamhaus_listed") is not None:
        if sc.get("spamhaus_listed"):
            z = sc.get("spamhaus_zones") or []
            auth.append("Spamhaus:命中" + (("(%s)" % "/".join(z)) if z else ""))
        else:
            auth.append("Spamhaus:未命中")
    if sc.get("vt_malicious") is not None:
        auth.append("VirusTotal:恶意%s" % sc.get("vt_malicious"))
    if auth:
        lines.append("权威滥用源  : " + "  ".join(auth))
    lines.append("-" * 60)
    verdict = "%d/100  %s" % (vd["risk_score"], vd["label"])
    lines.append("综合判定    : " + _color_level(c, vd["risk_level"], verdict))
    conf = agg.get("confidence") or {}

    def _cl(k):
        return {"high": "高", "medium": "中", "low": "低", "unknown": "未知"}.get(
            (conf.get(k) or {}).get("level"), "-")
    lines.append("置信度      : 地理:%s  代理:%s  VPN:%s  托管:%s  滥用:%s"
                 % (_cl("geo"), _cl("proxy"), _cl("vpn"), _cl("hosting"), _cl("abuse")))
    for note in agg.get("conflicts", []):
        lines.append(c.dim("备注        : " + note))
    lines.append("-" * 60)
    pf = agg.get("platform_fit") or []
    if pf:
        lines.append("平台适配度(启发式,非平台真实判定):")
        for item in pf:
            lines.append("  %s  %s  %s" % (item["label"], item["category"], item["reason"]))
        lines.append("-" * 60)
    dec = agg.get("decisions") or []
    if dec:
        lines.append("使用建议(启发式,综合IP画像):")
        for d in dec:
            lines.append("  %s  %-14s %s" % (d["label"], d["use"], d["reason"]))
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
        "type:%s" % (agg.get("ip_type") or "-"),
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
    geo = {}
    try:
        _, txt = http_get("http://ip-api.com/json/%s?fields=status,message,country,countryCode,city,timezone,lat,lon,isp"
                          % ip, timeout=args.timeout, retries=0)
        d = _j(txt)
        if d.get("status") == "success":
            geo = {"country": d.get("country"), "country_code": d.get("countryCode"),
                   "city": d.get("city"), "timezone": d.get("timezone"),
                   "lat": d.get("lat"), "lon": d.get("lon"), "isp": d.get("isp")}
    except Exception:
        pass
    env = env_consistency(geo)
    if args.json:
        print(json.dumps({"egress_ip": ip, "via": via, "geo": geo, "env": env},
                         ensure_ascii=False, indent=2, default=str))
    else:
        print("当前出口 IP: " + ip + "   (来源: " + str(via) + ")")
        if geo.get("country"):
            print("位置: %s %s   ISP: %s   时区: %s" % (
                geo.get("country"), geo.get("city") or "", geo.get("isp") or "", geo.get("timezone") or ""))
        print(render_env(env))
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
    ips = list(args.ips or [])
    if getattr(args, "file", None):
        try:
            with open(args.file, "r", encoding="utf-8-sig") as f:
                for line in f:
                    line = line.split("#")[0].strip()
                    if line:
                        ips.append(line)
        except Exception as e:  # noqa: BLE001
            print("读取 --file 失败: %s" % e, file=sys.stderr)
            return 2
    if not ips:
        print("请提供 IP（直接给参数，或用 --file 列出）", file=sys.stderr)
        return 2
    csv_rows = []
    rc = 0
    for idx, ip in enumerate(ips):
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
        if getattr(args, "env", False):
            try:
                agg["env"] = env_consistency(agg.get("geo") or {})
            except Exception:
                agg["env"] = {}
        if getattr(args, "regions", False):
            try:
                agg["regions"] = compute_regions(agg.get("geo") or {})
            except Exception:
                agg["regions"] = None
        csv_rows.append(_agg_to_row(agg))
        if args.json:
            print(render_json(agg))
        elif getattr(args, "brief", False):
            print(render_brief(agg))
        else:
            if idx:
                print()
            print(render_report(agg, color=color))
            if agg.get("env"):
                print(render_env(agg["env"]))
            if getattr(args, "platforms", False):
                extra = render_platforms(agg)
                if extra:
                    print(extra)
            if agg.get("regions"):
                print(render_regions(agg["regions"]))
        if getattr(args, "open", False):
            import webbrowser
            for u in ("https://www.abuseipdb.com/check/%s" % ip,
                      "https://iphub.info/?ip=%s" % ip):
                try:
                    webbrowser.open(u)
                except Exception:
                    pass
            print("已打开 abuseipdb / iphub 网页（IP 已带入，可人工核验）")
    if getattr(args, "csv", None):
        try:
            write_csv(csv_rows, args.csv)
            print("已导出 CSV: %s（%d 行）" % (args.csv, len(csv_rows)), file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            print("导出 CSV 失败: %s" % e, file=sys.stderr)
            rc = 2
    return rc


def cmd_watch(args):
    """轮询监控：目标 IP 关键属性变化，或监控自身出口 IP 漂移。"""
    color = not args.no_color and sys.stdout.isatty()
    c = C(color)
    from ipaddress import ip_address
    light = args.only or ["ipinfo", "ipapi", "proxycheck", "spamhaus"]

    def snap(agg):
        fl, vd, sc = agg["flags"], agg["verdict"], agg["scores"]
        return {
            "ip_type": agg.get("ip_type"),
            "proxy": fl.get("proxy"), "vpn": fl.get("vpn"),
            "hosting": fl.get("hosting"),
            "risk": vd.get("risk_score"),
            "spamhaus": sc.get("spamhaus_listed"),
        }

    def diff(old, new):
        ch = []
        for k in ("ip_type", "proxy", "vpn", "hosting", "risk", "spamhaus"):
            if old.get(k) != new.get(k):
                ch.append("%s: %s -> %s" % (k, old.get(k), new.get(k)))
        return ch

    print(c.b("监控开始：间隔 %ds，%s（Ctrl+C 停止）" %
              (args.interval, "出口 IP 漂移" if args.egress else "目标 IP 变化")))
    prev = {}
    prev_egress = None
    rounds = args.rounds or 10**9
    try:
        for r in range(rounds):
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            if args.egress:
                ip, via = get_egress_ip(args.timeout)
                if not ip:
                    print("[%s] 采样失败" % ts)
                elif prev_egress is None:
                    prev_egress = ip
                    print("[%s] 出口 IP: %s" % (ts, ip))
                elif ip != prev_egress:
                    print(c.yellow("[%s] ⚠️ 出口 IP 漂移: %s -> %s" % (ts, prev_egress, ip)))
                    prev_egress = ip
                else:
                    print(c.dim("[%s] 出口 IP 稳定: %s" % (ts, ip)))
            else:
                for ip in args.ips:
                    try:
                        ip_address(ip)
                    except ValueError:
                        continue
                    agg = check_ip(ip, only=light, timeout=args.timeout)
                    cur = snap(agg)
                    if ip in prev:
                        ch = diff(prev[ip], cur)
                        if ch:
                            print(c.yellow("[%s] ⚠️ %s 变化: %s" % (ts, ip, "; ".join(ch))))
                        else:
                            print(c.dim("[%s] %s 无变化 (risk=%s)" % (ts, ip, cur.get("risk"))))
                    else:
                        print("[%s] %s 基线: type=%s risk=%s" % (ts, ip, cur.get("ip_type"), cur.get("risk")))
                    prev[ip] = cur
            if r < rounds - 1:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n监控已停止")
    return 0


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
    pc.add_argument("ips", nargs="*", help="要检测的 IP（可多个；也可用 --file）")
    pc.add_argument("--file", default=None, help="从文件读 IP（每行一个，# 注释）")
    pc.add_argument("--csv", default=None, help="把结果导出 CSV")
    pc.add_argument("--only", type=_parse_only, default=None,
                    help="只用这些源，逗号分隔: " + ",".join(ALL_SOURCES))
    pc.add_argument("--json", action="store_true", help="输出 JSON")
    pc.add_argument("--brief", action="store_true", help="一行式简报")
    pc.add_argument("--open", action="store_true", help="检测后自动打开 abuseipdb/iphub 网页(IP已带入)")
    pc.add_argument("--env", action="store_true", help="附加环境一致性检测（本机时区/DNS vs IP，防关联指纹）")
    pc.add_argument("--platforms", action="store_true", help="追加各具体平台(X/FB/TikTok/OpenAI/Claude/PayPal/Netflix 等)可用度")
    pc.add_argument("--regions", action="store_true", help="追加各服务在 IP 所在国的可用性(OpenAI/Netflix/PayPal 等)")
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

    pw = sub.add_parser("watch", help="轮询监控：目标 IP 变化 / 出口 IP 漂移")
    pw.add_argument("ips", nargs="*", help="要监控的 IP（--egress 时不需要）")
    pw.add_argument("--egress", action="store_true", help="监控自身出口 IP 是否漂移")
    pw.add_argument("--interval", type=int, default=60, help="轮询间隔秒")
    pw.add_argument("--rounds", type=int, default=0, help="轮询轮数，0=直到 Ctrl+C")
    pw.add_argument("--only", type=_parse_only, default=None, help="监控使用的源（默认轻量集）")
    pw.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    pw.add_argument("--no-color", action="store_true")
    pw.set_defaults(func=cmd_watch)
    return p


def main(argv=None):
    _setup_console()
    argv = argv if argv is not None else sys.argv[1:]
    # 简化：允许直接 `ipcheck.py 8.8.8.8`（等价于 check）
    # 简化：允许直接 `ipcheck.py 8.8.8.8` 或 `ipcheck.py --file x.txt`（等价于 check）
    if argv and argv[0] not in ("check", "myip", "stability", "open", "watch", "-h", "--help"):
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
