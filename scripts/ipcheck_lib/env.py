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


__all__ = ['_local_utc_offset', 'get_dns_resolver', 'env_consistency', 'EGRESS_ENDPOINTS', 'get_egress_ip']
