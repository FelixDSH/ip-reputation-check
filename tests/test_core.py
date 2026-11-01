#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_core.py — 核心逻辑单元测试
===============================

覆盖：各源 parser 字段映射、_vote 冲突、_coherent_geo、compute_risk 阈值、
_conf_bool 平票、classify_ip_type、CSV 公式注入、iphub 游客/验证码分支。

打桩打在 ipcheck_lib.sources（源适配器所在模块），不联网。
运行：  python tests/test_core.py
"""
import os
import sys
import json
import tempfile
import unittest
import importlib.util
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

spec = importlib.util.spec_from_file_location("ic", os.path.join(ROOT, "scripts", "ipcheck.py"))
ic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ic)

import ipcheck_lib.sources as S  # noqa: E402  源适配器现在在此模块，需在此打桩


def fake_get_json(obj):
    def _f(url, headers=None, timeout=None, retries=1):
        return 200, json.dumps(obj)
    return _f


def fake_get_text(text):
    def _f(url, headers=None, timeout=None, retries=1):
        return 200, text
    return _f


class TestParsers(unittest.TestCase):
    def test_ipapi(self):
        obj = {"status": "success", "country": "United States", "countryCode": "US",
               "regionName": "California", "city": "Mountain View", "lat": 1.0, "lon": 2.0,
               "timezone": "America/Los_Angeles", "isp": "Google", "org": "Google LLC",
               "as": "AS15169 Google LLC", "reverse": "dns.google", "mobile": False,
               "proxy": False, "hosting": True}
        with mock.patch.object(S, "http_get", fake_get_json(obj)):
            d = ic.src_ipapi("8.8.8.8", 5)
        self.assertEqual(d["country_code"], "US")
        self.assertEqual(d["hosting"], True)
        self.assertEqual(d["asn_org"], "AS15169 Google LLC")

    def test_ipapi_fail(self):
        with mock.patch.object(S, "http_get", fake_get_json({"status": "fail", "message": "x"})):
            with self.assertRaises(RuntimeError):
                ic.src_ipapi("1.2.3.4", 5)

    def test_proxycheck(self):
        obj = {"status": "ok", "8.8.8.8": {"proxy": "no", "type": "Business",
                                            "asn": "AS15169", "country": "United States",
                                            "isocode": "US", "risk": 0}}
        with mock.patch.object(S, "http_get", fake_get_json(obj)):
            d = ic.src_proxycheck("8.8.8.8", 5)
        self.assertEqual(d["proxy"], False)
        self.assertEqual(d["type"], "Business")

    def test_stopforumspam(self):
        obj = {"success": 1, "ip": {"value": "1.2.3.4", "frequency": 85, "appears": 1}}
        with mock.patch.object(S, "http_get", fake_get_json(obj)):
            d = ic.src_stopforumspam("1.2.3.4", 5)
        self.assertEqual(d["frequency"], 85)

    def test_blocklistde(self):
        with mock.patch.object(S, "http_get", fake_get_json({"attacks": 3, "reports": 2})):
            d = ic.src_blocklistde("1.2.3.4", 5)
        self.assertEqual(d["attacks"], 3)

    def test_dbip(self):
        obj = {"countryCode": "JP", "countryName": "Japan", "stateProv": "Kanagawa", "city": "Kawasaki"}
        with mock.patch.object(S, "http_get", fake_get_json(obj)):
            d = ic.src_dbip("212.68.185.88", 5)
        self.assertEqual(d["country_code"], "JP")
        self.assertEqual(d["city"], "Kawasaki")

    def test_scamalytics_html(self):
        html = "<div>Fraud Score: 42</div><span>High Risk</span>"
        with mock.patch.object(S, "http_get", fake_get_text(html)), \
                mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SCAMALYTICS_USER", None)
            os.environ.pop("SCAMALYTICS_KEY", None)
            d = ic.src_scamalytics("1.2.3.4", 5)
        self.assertEqual(d["fraud_score"], 42)
        self.assertEqual(d["risk"], "High")
        self.assertEqual(d["via"], "html")

    def test_iphub_guest_success(self):
        sample = {"success": True, "data": {"block": 2, "isp": "X", "asn": 1, "countryCode": "JP",
                  "countryName": "Japan", "hostname": "h",
                  "proxyType": {"proxy": False, "tor": False, "hosting": True,
                                "residentialProxy": False, "relay": False, "cloudGaming": False}}}
        with mock.patch.object(S, "http_post_json", lambda *a, **k: (200, json.dumps(sample))), \
                mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IPHUB_API_KEY", None)
            d = ic.src_iphub("1.2.3.4", 5)
        self.assertEqual(d["block"], 2)
        self.assertFalse(d["proxy"])
        self.assertTrue(d["hosting"])

    def test_iphub_captcha(self):
        cap = {"success": False, "error": "Human verification required", "captchaRequired": True}
        with mock.patch.object(S, "http_post_json", lambda *a, **k: (200, json.dumps(cap))), \
                mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IPHUB_API_KEY", None)
            with self.assertRaises(RuntimeError) as cm:
                ic.src_iphub("1.2.3.4", 5)
        self.assertIn("人机验证", str(cm.exception))

    def test_spamhaus_fakeip_untrusted(self):
        # Fake-IP DNS 返回 198.18.0.15 → 不能当“未命中”，必须报不可信
        with mock.patch.object(S, "_dns_query_a", lambda *a, **k: "198.18.0.15"):
            with self.assertRaises(RuntimeError) as cm:
                ic.src_spamhaus("1.2.3.4", 5)
        self.assertIn("不可信", str(cm.exception))

    def test_spamhaus_not_listed(self):
        import socket as _s

        def boom(*a, **k):
            raise _s.gaierror()
        with mock.patch.object(S, "_dns_query_a", boom):
            d = ic.src_spamhaus("1.2.3.4", 5)
        self.assertFalse(d["listed"])


class TestScoring(unittest.TestCase):
    def test_risk_thresholds(self):
        self.assertEqual(ic.compute_risk(0, None, False, False, False, False, False)[1], "clean")
        self.assertEqual(ic.compute_risk(0, None, False, False, True, False, False)[0], 10)  # hosting
        self.assertEqual(ic.compute_risk(0, None, True, True, False, False, False)[1], "medium")  # proxy+vpn=65
        self.assertEqual(ic.compute_risk(0, None, False, False, False, True, False)[0], 60)  # tor
        self.assertEqual(ic.compute_risk(85, None, False, False, False, False, False)[1], "high")

    def test_risk_dedup_correlated_hosting(self):
        # 代理+VPN 已计分时，hosting 不再叠加（避免 30+35+10=75 的重复计分）
        self.assertEqual(ic.compute_risk(0, None, True, True, True, False, False)[0], 65)

    def test_conf_bool_tie_uses_priority(self):
        c = ic._conf_bool([("proxycheck", False), ("ipapi", True)])  # 平票取优先源
        self.assertFalse(c["value"])
        self.assertEqual(c["level"], "low")

    def test_conf_bool_high(self):
        c = ic._conf_bool([("ipinfo", True), ("ipapi", True), ("ipwhois", True)])
        self.assertTrue(c["value"])
        self.assertEqual(c["level"], "high")

    def test_classify_type(self):
        base = {"tor": False, "vpn": False, "proxy": False, "hosting": False, "mobile": False}
        self.assertEqual(ic.classify_ip_type(base, {"type": "Business"}, "Acme Corp"), "企业网络")
        self.assertEqual(ic.classify_ip_type({**base, "hosting": True}, {}, "Google LLC"), "机房/云主机")
        self.assertEqual(ic.classify_ip_type({**base, "mobile": True}, {}, "China Mobile"), "移动网络(4G/5G)")
        self.assertEqual(ic.classify_ip_type({**base, "vpn": True}, {}, "X"), "VPN")
        self.assertEqual(ic.classify_ip_type(base, {}, "Some University"), "教育网")


class TestAggregateHelpers(unittest.TestCase):
    def test_empty_results_is_insufficient_not_clean(self):
        # 无任何源成功 → 必须“无法判定”，不能判成干净住宅
        agg = ic.aggregate("1.2.3.4", [])
        self.assertEqual(agg["verdict"]["risk_level"], "unknown")
        self.assertIsNone(agg["verdict"]["risk_score"])
        self.assertIn("数据不足", agg["ip_type"])
        self.assertEqual(agg["decisions"], [])

    def test_vote_records_conflict(self):
        conflicts = []
        val = ic._vote(conflicts, "Proxy", [("proxycheck", False), ("ipapi", True)])
        self.assertFalse(val)
        self.assertEqual(len(conflicts), 1)
        self.assertIn("不一致", conflicts[0])

    def test_coherent_geo_single_source(self):
        srcs = {
            "ipapi": {"country": "United States", "country_code": "US", "region": "Virginia",
                      "city": "Ashburn", "lat": 39.0, "lon": -77.0, "timezone": "America/New_York"},
            "ipinfo": {"country": "US", "region": "California", "city": "Mountain View"},
        }
        g = ic._coherent_geo(srcs)
        self.assertEqual(g["city"], "Ashburn")
        self.assertEqual(g["region"], "Virginia")
        self.assertEqual(g["geo_source"], "ip-api.com")


class TestCsv(unittest.TestCase):
    def test_csv_formula_injection_escaped(self):
        rows = [{"ip": "1.2.3.4", "city": "=HYPERLINK(1)", "country": "+1", "asn_org": "@x"}]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "o.csv")
            ic.write_csv(rows, p)
            with open(p, encoding="utf-8-sig") as f:
                lines = f.read().splitlines()
        self.assertIn("'=HYPERLINK(1)", lines[1])
        self.assertIn("'+1", lines[1])
        self.assertIn("'@x", lines[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
