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

def _csv_safe(v):
    """防 CSV 公式注入：以 = + - @ 等开头的单元格前置单引号。"""
    s = "" if v is None else str(v)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s

def write_csv(rows, path):
    """把检测结果导出 CSV（UTF-8-BOM，Excel 可直接打开；已做公式注入防护）。"""
    import csv
    cols = ["ip", "country", "city", "asn_org", "ip_type", "proxy", "vpn", "hosting",
            "mobile", "fraud_score", "abuse_confidence", "spamhaus", "vt_malicious",
            "risk_score", "risk_level", "geo_conf", "proxy_conf", "abuse_conf"]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in rows:
            w.writerow([_csv_safe(r.get(c, "")) for c in cols])
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


__all__ = ['compute_regions', '_csv_safe', 'write_csv', '_agg_to_row']
