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

def render_platforms(agg):
    rows = agg.get("platforms") or []
    if not rows:
        return ""
    lines = ["站点适配度(规则推算,非实测; 红灯=机房/代理/VPN 易触发风控，不代表一定不可用或会封号):"]
    for r in rows:
        lines.append("  %s  %-18s %s" % (r["label"], r["platform"], r["note"]))
    return "\n".join(lines)

def render_regions(reg):
    lines = ["服务地区可用性(按 IP 所在国 %s，近似，以官方为准):" % (reg.get("country") or "?"), ]
    for s in reg.get("services", []):
        lines.append("  %s  %-16s %s" % (s["label"], s["service"], s["note"]))
    return "\n".join(lines)

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
    reg = net.get("registry") or {}
    if reg.get("handle") or reg.get("org") or reg.get("name"):
        lines.append("登记(RDAP)  : %s / %s / %s" % (
            reg.get("handle") or "-", reg.get("range") or "-", reg.get("org") or reg.get("name") or "-"))
    rt = net.get("routing") or {}
    if rt.get("prefix") or rt.get("origin_asn") is not None:
        lines.append("路由(BGP)   : %s announced=%s origin AS%s (%s)" % (
            rt.get("prefix") or "-", rt.get("announced"), rt.get("origin_asn") or "?",
            rt.get("origin_holder") or "-"))
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
    if sc.get("spamhaus_malicious") is not None:
        z = sc.get("spamhaus_zones") or []
        if sc.get("spamhaus_malicious"):
            auth.append("Spamhaus:恶意名单命中" + (("(%s)" % "/".join(z)) if z else ""))
        elif sc.get("spamhaus_policy"):
            auth.append("Spamhaus:仅策略名单(PBL,发信策略,非恶意行为)")
        else:
            auth.append("Spamhaus:未命中")
    if sc.get("vt_malicious") is not None:
        auth.append("VirusTotal:恶意%s" % sc.get("vt_malicious"))
    if auth:
        lines.append("权威滥用源  : " + "  ".join(auth))
    lines.append("-" * 60)
    rs = vd.get("risk_score")
    verdict = ("%d/100  %s" % (rs, vd["label"])) if rs is not None else vd["label"]
    lines.append("规则提示分  : " + _color_level(c, vd["risk_level"], verdict) + c.dim("  (经验规则分,非概率)"))
    conf = agg.get("confidence") or {}

    def _cl(k):
        return {"high": "高", "medium": "中", "low": "低", "unknown": "未知"}.get(
            (conf.get(k) or {}).get("level"), "-")
    lines.append("置信度      : 地理:%s  代理:%s  VPN:%s  托管:%s  滥用:%s"
                 % (_cl("geo"), _cl("proxy"), _cl("vpn"), _cl("hosting"), _cl("abuse")))
    # 逐字段证据（支持/反对 + 强度）——可追溯
    ev = []
    for label, key in (("代理", "proxy"), ("VPN", "vpn"), ("托管", "hosting"), ("地理", "geo")):
        cc = conf.get(key) or {}
        if not cc:
            continue
        if key == "geo":
            vtxt = str(cc.get("value")) if cc.get("value") else "未知"
        else:
            vtxt = "是" if cc.get("value") is True else ("否" if cc.get("value") is False else "未知")
        ev.append("  %-3s=%s 强度:%s 支持:%s 反对:%s" % (
            label, vtxt, _cl(key),
            ",".join(cc.get("support") or []) or "-",
            ",".join(cc.get("oppose") or []) or "-"))
    if ev:
        lines.append("证据强度    :")
        lines.extend(ev)
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
    lines.append(c.dim("ℹ️ 多源规则初筛，非概率、非实测；“干净/风险”仅表示证据倾向，不等于安全结论。"))
    lines.append(c.b("=" * 60))
    return "\n".join(lines)

def render_brief(agg):
    """一行式简报，便于快速扫读。"""
    geo, net, fl, sc, vd = agg["geo"], agg["network"], agg["flags"], agg["scores"], agg["verdict"]
    loc = ",".join([x for x in [geo.get("country"), geo.get("city")] if x]) or "-"
    abuse = sc.get("abuse_confidence")
    fs = sc.get("fraud_score")
    flag = {"clean": "🟢", "low": "🟡", "medium": "🟠", "high": "🔴", "unknown": "⚪"}.get(vd["risk_level"], "")
    rs = vd.get("risk_score")
    risk_txt = ("%s %d/100" % (flag, rs)) if rs is not None else (flag + " 数据不足/无法判定")
    parts = [
        agg["ip"], loc, (net.get("asn_org") or "-"),
        "type:%s" % (agg.get("ip_type") or "-"),
        "proxy:%s vpn:%s host:%s" % (_fmt_bool(fl.get("proxy")), _fmt_bool(fl.get("vpn")), _fmt_bool(fl.get("hosting"))),
        "fraud:%s" % (fs if fs is not None else "-"),
        "abuse:%s" % ((str(abuse) + "%") if abuse is not None else "-"),
        "ipsum:%s" % ("命中" if sc.get("ipsum_listed") else ("未" if sc.get("ipsum_listed") is not None else "-")),
        risk_txt,
    ]
    return " | ".join(parts)

def render_json(agg):
    return json.dumps(agg, ensure_ascii=False, indent=2)


__all__ = ['render_platforms', 'render_regions', 'render_env', 'C', '_fmt_bool', '_color_level', 'render_report', 'render_brief', 'render_json']
