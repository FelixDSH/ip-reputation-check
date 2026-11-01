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
from ipcheck_lib.sources import *  # noqa: F401,F403
from ipcheck_lib import sources as _sources  # noqa: F401

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
    """布尔结论。与 _conf_bool 共用同一「源等级加权多数」判决，保证值=置信度值（不再主结论/置信度打架）。"""
    known = [(s, v) for s, v in votes if v is not None]
    if not known:
        return None
    c = _conf_bool(votes)
    val = c["value"]
    if any(v != val for _, v in known):
        detail = ", ".join("%s=%s" % (SOURCE_LABEL.get(s, s), ("是" if v else "否")) for s, v in known)
        lvl_cn = {"high": "高", "medium": "中", "low": "低", "unknown": "未知"}.get(c.get("level"), "?")
        conflicts.append("%s 源间不一致（%s），按加权多数采用「%s」（置信度:%s）"
                         % (flag_name, detail, "是" if val else "否", lvl_cn))
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
    support = [SOURCE_LABEL.get(s, s) for s, v in known if v == val]
    oppose = [SOURCE_LABEL.get(s, s) for s, v in known if v != val]
    return {"level": lvl, "n": n, "value": val, "support": support, "oppose": oppose}

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
    support = [SOURCE_LABEL.get(s, s) for s, v in known if v == val]
    oppose = [SOURCE_LABEL.get(s, s) for s, v in known if v != val]
    return {"level": lvl, "n": n, "value": val, "support": support, "oppose": oppose}

def _platform_level(score):
    if score < 25:
        return "low", "🟢 较适合(推测)"
    if score < 55:
        return "medium", "🟡 谨慎"
    return "high", "🔴 易触发风控"

def _platform_fit(flags, geo, net, scores, ip_type=""):
    """基于 IP 画像给各平台类别的「可用度风险」启发式评分。"""
    abuse_hit = bool(scores.get("spamhaus_malicious")) or \
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
            reasons.append(_type_reason(ip_type))
        out.append({"category": cat, "score": score, "level": lvl,
                    "label": label, "reason": ", ".join(reasons)})
    return out

def _type_reason(ip_type):
    """无风险信号时，按 IP 类型给出中性描述，避免把企业/教育网误写成‘住宅’。"""
    t = ip_type or ""
    if "住宅" in t:
        return "住宅/普通网络，风险低"
    if "移动" in t:
        return "移动网络(较优)"
    if "企业" in t:
        return "企业网络(相对可信)"
    if "教育" in t:
        return "教育网(相对可信)"
    if "政府" in t:
        return "政府/机构网络"
    return "普通网络(类型未细分)"

def _abuse_hit(scores):
    return bool(scores.get("spamhaus_malicious")) or \
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
    org_net = any(k in t for k in ("企业", "教育", "政府"))
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
    elif org_net:
        add("注册社媒/AI 账号", "warn", "企业/机构网络：注册一般可用，但共享出口或异常行为仍可能触发验证")
    else:
        add("注册社媒/AI 账号", "warn", "网络类型未细分，建议先用浏览器环境实测")

    # 长期养号
    if (residential or mobile) and not abuse:
        add("长期养号", "ok", "住宅/移动 IP + 无滥用，适合养号（务必保持出口稳定）")
    elif datacenter or anon:
        add("长期养号", "no", "机房/代理/VPN IP 不利于长期养号，易被清理")
    elif org_net:
        add("长期养号", "warn", "企业/机构网络：独享出口可养号，共享出口风险高")
    else:
        add("长期养号", "warn", "存在风险信号，养号需谨慎")

    # 爬虫/采集
    if datacenter and not abuse:
        add("爬虫/数据采集", "ok", "机房 IP 适合高并发采集（注意目标站反爬）")
    elif abuse:
        add("爬虫/数据采集", "warn", "有滥用记录，部分站点会直接封")
    else:
        add("爬虫/数据采集", "warn", "可用，但非机房 IP 做采集成本高/易触发")

    # 电商/支付
    if datacenter or anon or abuse:
        add("电商/支付", "no", "风控最严，机房/代理/滥用 IP 通常不可用(规则推算)")
    else:
        add("电商/支付", "warn", "住宅/企业 IP 可试，但支付类仍需 KYC 与行为验证")

    # 流媒体
    if vpn:
        add("流媒体解锁", "warn", "VPN 可能被封（Netflix 等），需实测")
    elif datacenter:
        add("流媒体解锁", "warn", "机房 IP 多数流媒体会拦，原生住宅更稳")
    elif residential or mobile:
        add("流媒体解锁", "ok", "住宅/移动 IP 解锁成功率较高")
    else:
        add("流媒体解锁", "warn", "非住宅/移动网络，流媒体解锁成功率一般")
    return out

def compute_platforms(flags, geo, net, scores, ip_type=""):
    """按具体平台给可用度（基于平台规则库 × 类别基线分）。"""
    cat_scores = {item["category"]: item["score"] for item in _platform_fit(flags, geo, net, scores, ip_type)}
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

def aggregate(ip, results):
    get = {r["source"]: r for r in results}
    ok_count = sum(1 for r in results if r.get("ok"))
    srcs = {name: (get[name]["data"] if get.get(name) and get[name]["ok"] else {})
            for name in _sources.SOURCES}

    ipinfo, ipapi, ipwho = srcs["ipinfo"], srcs["ipapi"], srcs["ipwhois"]
    proxycheck, scam = srcs["proxycheck"], srcs["scamalytics"]
    iphub, abuse = srcs["iphub"], srcs["abuseipdb"]
    sfs = srcs["stopforumspam"]
    bl = srcs["blocklistde"]
    ipsum = srcs["ipsum"]
    maxmind, dbip = srcs["maxmind"], srcs["dbip"]
    rdap, bgp, tor_exit = srcs["rdap"], srcs["ripe_bgp"], srcs["tor_exit"]

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
    # Tor：官方出口名单优先（权威）；无该源时回退到 AbuseIPDB / iphub 标记
    if bool(get.get("tor_exit") and get["tor_exit"]["ok"]):
        tor = bool(tor_exit.get("is_tor"))
    else:
        tor = _pick_bool(abuse.get("is_tor"), iphub.get("tor"))
    ip_type = classify_ip_type(
        {"tor": tor, "vpn": vpn, "proxy": proxy, "hosting": hosting, "mobile": mobile},
        {"type": proxycheck.get("type")}, asn_org)

    fraud_score = _to_int(scam.get("fraud_score"))
    fraud_risk = scam.get("risk")
    abuse_conf = _to_int(abuse.get("abuse_confidence"))

    spamhaus, vt = srcs["spamhaus"], srcs["virustotal"]
    spamhaus_ok = bool(get.get("spamhaus") and get["spamhaus"]["ok"])
    vt_ok = bool(get.get("virustotal") and get["virustotal"]["ok"])
    spamhaus_listed = bool(spamhaus.get("listed")) if spamhaus_ok else None
    spamhaus_malicious = bool(spamhaus.get("malicious")) if spamhaus_ok else None
    spamhaus_policy = bool(spamhaus.get("policy")) if spamhaus_ok else None
    vt_mal = _to_int(vt.get("malicious")) if vt_ok else None

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
    if spamhaus_malicious:
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
    if spamhaus_malicious or (vt_mal and vt_mal > 0):
        conf_abuse = {"level": "high", "note": "权威源命中"}
    elif (abuse_conf and abuse_conf > 0) or (sfs_freq and sfs_freq > 0) or \
            (bl_attacks and bl_attacks > 0) or ipsum_listed:
        conf_abuse = {"level": "medium", "note": "仅社区/聚合命中"}
    elif not spamhaus_ok and not vt_ok:
        conf_abuse = {"level": "unknown", "note": "权威源不可用(Spamhaus/VT)，无权威结论"}
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
    scores_view = {"spamhaus_malicious": spamhaus_malicious, "vt_malicious": vt_mal,
                   "abuse_confidence": abuse_conf, "ipsum_listed": ipsum_listed}
    net_view = {"asn_org": asn_org}
    platform_fit = _platform_fit(flags_view, geo, net_view, scores_view, ip_type)
    decisions = compute_decisions(ip_type, flags_view, scores_view, geo)
    platforms = compute_platforms(flags_view, geo, net_view, scores_view, ip_type)

    # 数据不足：没有任何源成功 → 结论必须是“无法判定”，绝不能当“干净住宅”
    if ok_count == 0:
        ip_type = "未知（数据不足）"
        risk_score, risk_level = None, "unknown"
        platform_fit, platforms, decisions = [], [], []
        confidence["abuse"] = {"level": "unknown", "note": "无数据，无法判定"}
        confidence["geo"] = {"level": "unknown", "n": 0}
        confidence["proxy"] = {"level": "unknown", "n": 0}
        confidence["vpn"] = {"level": "unknown", "n": 0}
        confidence["hosting"] = {"level": "unknown", "n": 0}

    return {
        "ip": ip,
        "ip_type": ip_type,
        "geo": geo,
        "network": {"asn_org": asn_org, "isp": isp, "hostname": hostname,
                    "usage_type": abuse.get("usage_type"), "type": proxycheck.get("type"),
                    "registry": ({"handle": rdap.get("handle"), "name": rdap.get("name"),
                                  "org": rdap.get("org"),
                                  "range": ("%s - %s" % (rdap.get("start"), rdap.get("end"))
                                            if rdap.get("start") else None),
                                  "country": rdap.get("country")}
                                 if get.get("rdap") and get["rdap"]["ok"] else {}),
                    "routing": ({"prefix": bgp.get("prefix"), "announced": bgp.get("announced"),
                                 "origin_asn": bgp.get("origin_asn"),
                                 "origin_holder": bgp.get("origin_holder")}
                                if get.get("ripe_bgp") and get["ripe_bgp"]["ok"] else {})},
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
                   "spamhaus_malicious": spamhaus_malicious, "spamhaus_policy": spamhaus_policy,
                   "vt_malicious": vt_mal, "vt_reputation": vt.get("reputation"),
                   "tor_official": (bool(tor_exit.get("is_tor"))
                                    if get.get("tor_exit") and get["tor_exit"]["ok"] else None)},
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

def compute_risk(fraud, abuse, proxy, vpn, hosting, tor, mobile, free_pts=0):
    """经验加权「规则分」（权重见 RISK_W_*，非校准概率、非概率百分比）。
    去相关：已有 代理/VPN 时不再叠加 hosting（三者常来自同一来源，避免重复计分）。"""
    ext = max([x for x in (fraud, abuse) if x is not None], default=0)
    pts = 0
    if proxy:
        pts += RISK_W_PROXY
    if vpn:
        pts += RISK_W_VPN
    if hosting and not (proxy or vpn):
        pts += RISK_W_HOSTING
    if tor:
        pts += RISK_W_TOR
    if mobile:
        pts += RISK_W_MOBILE
    pts = max(0, pts)
    score = min(100, max(ext, pts, free_pts))
    if score < RISK_T_CLEAN:
        level = "clean"
    elif score < RISK_T_LOW:
        level = "low"
    elif score < RISK_T_MEDIUM:
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
        "unknown": "\u26AA 数据不足 / 无法判定",
    }.get(level, level)

def _local_agg(ip):
    """私有/环回/保留/CGNAT 等非公网地址：不向公共信誉接口发送，直接本地判定。"""
    geo = {"country": None, "country_code": None, "region": None, "city": None,
           "lat": None, "lon": None, "timezone": None, "geo_source": None}
    conf = {k: {"level": "unknown", "n": 0} for k in ("geo", "proxy", "vpn", "hosting")}
    conf["abuse"] = {"level": "unknown", "note": "本地/保留地址，无需公网查询"}
    return {
        "ip": ip, "ip_type": "私有/保留地址（本地）", "geo": geo,
        "network": {"asn_org": None, "isp": None, "hostname": None, "usage_type": None, "type": None},
        "flags": {"proxy": None, "vpn": None, "hosting": None, "mobile": None,
                  "tor": None, "residential_proxy": None},
        "scores": {k: None for k in (
            "fraud_score", "fraud_risk", "abuse_confidence", "abuse_reports", "proxycheck_risk",
            "iphub_block", "sfs_frequency", "bl_attacks", "ipsum_listed", "ipsum_score",
            "spamhaus_listed", "spamhaus_zones", "spamhaus_malicious", "spamhaus_policy",
            "vt_malicious", "vt_reputation")},
        "verdict": {"risk_score": None, "risk_level": "unknown", "label": "⚪ 本地/保留地址，跳过公网查询"},
        "confidence": conf, "platform_fit": [], "platforms": [], "decisions": [],
        "conflicts": [], "sources": [],
    }


def check_ip(ip, only=None, timeout=DEFAULT_TIMEOUT):
    # 非公网地址（私网/环回/保留/CGNAT）不发外网查询
    try:
        from ipaddress import ip_address as _ipa
        if not _ipa(ip).is_global:
            return _local_agg(ip)
    except ValueError:
        pass
    names = [s for s in (only or _sources.ALL_SOURCES) if s in _sources.SOURCES]
    results = []
    with cf.ThreadPoolExecutor(max_workers=len(names)) as ex:
        futs = {ex.submit(_sources.SOURCES[n], ip, timeout): n for n in names}
        for fut in cf.as_completed(futs):
            n = futs[fut]
            try:
                d = fut.result()
                if not d:  # 空响应 / 无有效字段 ≠ 成功
                    results.append({"source": n, "ok": False, "data": {}, "error": "空响应/无有效字段"})
                else:
                    results.append({"source": n, "ok": True, "data": d, "error": None})
            except Exception as e:  # noqa: BLE001
                results.append({"source": n, "ok": False, "data": {}, "error": str(e)})
    # 保持稳定顺序
    order = {n: i for i, n in enumerate(_sources.ALL_SOURCES)}
    results.sort(key=lambda r: order.get(r["source"], 99))
    return aggregate(ip, results)


__all__ = ['_coherent_geo', '_vote', '_conf_bool', '_conf_cat', '_platform_level', '_platform_fit', '_type_reason', '_abuse_hit', 'compute_decisions', 'compute_platforms', 'aggregate', '_pick_bool', '_hosting_from_org', 'classify_ip_type', 'compute_risk', 'risk_label', 'check_ip', '_local_agg']


