#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_consistency.py — IP 类型 × 文案一致性自检
==============================================

目的：防止「ip_type=企业网络，但平台适配度/使用建议却写住宅或类型不确定」这类文案打架 bug 复发。
做法：枚举所有 ip_type，跑 _platform_fit / compute_decisions / compute_platforms，
      断言「文案里出现的网络类型描述」必须与 ip_type 自洽。

运行：  python tests/test_consistency.py
退出码：0=全部通过；1=有失败（会打印具体用例）
"""
import os
import sys
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location("ic", os.path.join(ROOT, "scripts", "ipcheck.py"))
ic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ic)

GEO = {"country_code": "US", "country": "United States", "lon": -77.0}
NO_SCORE = {}

NON_RES = {"机房/云主机", "企业网络", "教育网", "政府/机构"}
ANON = {"VPN", "代理/公共代理", "Tor 出口"}
RESID = {"住宅/ISP", "住宅/普通ISP（推断）"}
MOBILE = {"移动网络(4G/5G)"}

CASES = [
    ("住宅/ISP", {}),
    ("住宅/普通ISP（推断）", {}),
    ("移动网络(4G/5G)", {"mobile": True}),
    ("机房/云主机", {"hosting": True}),
    ("企业网络", {}),
    ("教育网", {}),
    ("政府/机构", {}),
    ("VPN", {"vpn": True}),
    ("代理/公共代理", {"proxy": True}),
    ("Tor 出口", {"tor": True}),
]


def flags(base):
    f = {"proxy": False, "vpn": False, "hosting": False, "mobile": False, "tor": False}
    f.update(base)
    return f


failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def run():
    for ip_type, extra in CASES:
        fl = flags(extra)
        net = {"asn_org": "Acme Corp"}

        # 1) _platform_fit：无风险信号时默认文案必须与类型一致
        pf = ic._platform_fit(fl, GEO, net, NO_SCORE, ip_type)
        check(len(pf) == len(ic.PLATFORM_PROFILES), "[%s] platform_fit 条数不对" % ip_type)
        for item in pf:
            reason = item["reason"]
            if ip_type in NON_RES:
                check("住宅/普通网络" not in reason,
                      "[%s] platform_fit 把类型写成住宅: %s -> %s" % (ip_type, item["category"], reason))
            if ip_type == "企业网络":
                check("企业" in reason, "[%s] 文案未体现企业: %s" % (ip_type, reason))
            if ip_type == "教育网":
                check("教育" in reason, "[%s] 文案未体现教育: %s" % (ip_type, reason))
            if ip_type == "政府/机构":
                check("政府" in reason, "[%s] 文案未体现政府: %s" % (ip_type, reason))
            if ip_type == "机房/云主机":
                check("机房" in reason, "[%s] 文案未体现机房: %s" % (ip_type, reason))
            if ip_type in ANON:
                token = {"VPN": "VPN", "代理/公共代理": "代理", "Tor 出口": "Tor"}[ip_type]
                check(token in reason, "[%s] 文案未体现匿名类型: %s" % (ip_type, reason))
            if ip_type in RESID:
                check("住宅" in reason, "[%s] 住宅类型文案未体现住宅: %s" % (ip_type, reason))
            if ip_type in MOBILE:
                check("移动" in reason, "[%s] 移动类型文案未体现移动: %s" % (ip_type, reason))

        # 2) compute_decisions：不得出现"类型不确定"；注册建议必须贴合类型
        dec = ic.compute_decisions(ip_type, fl, NO_SCORE, GEO)
        check(len(dec) == 5, "[%s] decisions 条数不对" % ip_type)
        reg = dec[0]
        for d in dec:
            check("类型不确定" not in d["reason"],
                  "[%s] decisions 出现\"类型不确定\": %s -> %s" % (ip_type, d["use"], d["reason"]))
        if ip_type in ANON:
            check(any(t in reg["reason"] for t in ("代理", "VPN", "Tor")),
                  "[%s] 注册建议未体现匿名类型: %s" % (ip_type, reg["reason"]))
        if ip_type == "机房/云主机":
            check("机房" in reg["reason"], "[%s] 注册建议未体现机房: %s" % (ip_type, reg["reason"]))
        if ip_type in ("企业网络", "教育网", "政府/机构"):
            check(("企业" in reg["reason"] or "机构" in reg["reason"]),
                  "[%s] 注册建议未体现机构属性: %s" % (ip_type, reg["reason"]))
        if ip_type in RESID or ip_type in MOBILE:
            check(("住宅" in reg["reason"] or "移动" in reg["reason"]),
                  "[%s] 注册建议未体现住宅/移动: %s" % (ip_type, reg["reason"]))

        # 3) compute_platforms 正常产出
        plats = ic.compute_platforms(fl, GEO, net, NO_SCORE, ip_type)
        check(len(plats) == len(ic.PLATFORMS), "[%s] platforms 条数不对" % ip_type)


def main():
    run()
    if failures:
        print("❌ 一致性自检失败 %d 项：" % len(failures))
        for f in failures:
            print("   - " + f)
        return 1
    print("✅ 一致性自检通过：%d 种 IP 类型 × 平台适配度/使用建议/平台可用度 文案均与类型自洽" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
