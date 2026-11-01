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
            raise _s.gaierror(11001, "Host not found")  # 明确的 NXDOMAIN
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

    def test_conf_no_count_boost_without_A(self):
        # 仅 B/C 源一致，不因数量升为"高"（独立性未知）
        c = ic._conf_bool([("iphub", True), ("scamalytics", True), ("ipsum", True)])
        self.assertTrue(c["value"])
        self.assertEqual(c["level"], "medium")
        self.assertEqual(c.get("independence"), "unknown")

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


class TestP1Evidence(unittest.TestCase):
    def test_rdap_parse(self):
        obj = {"handle": "NET-8-8-8-0-2", "name": "GOGL", "startAddress": "8.8.8.0",
               "endAddress": "8.8.8.255", "country": "US", "status": ["active"],
               "entities": [{"roles": ["registrant"],
                             "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]]}]}
        with mock.patch.object(S, "http_get", fake_get_json(obj)):
            d = ic.src_rdap("8.8.8.8", 5)
        self.assertEqual(d["org"], "Google LLC")
        self.assertEqual(d["handle"], "NET-8-8-8-0-2")
        self.assertEqual(d["start"], "8.8.8.0")

    def test_bgp_parse(self):
        obj = {"data": {"announced": True, "resource": "8.8.8.0/24",
                        "asns": [{"asn": 15169, "holder": "GOOGLE"}]}}
        with mock.patch.object(S, "http_get", fake_get_json(obj)):
            d = ic.src_ripe_bgp("8.8.8.8", 5)
        self.assertTrue(d["announced"])
        self.assertEqual(d["origin_asn"], 15169)
        self.assertEqual(d["prefix"], "8.8.8.0/24")

    def test_tor_official_list(self):
        import time as _t
        def fake(timeout, refresh=False):
            return {"1.2.3.4"}, _t.time()
        with mock.patch.object(S, "_load_tor", fake):
            self.assertTrue(ic.src_tor_exit("1.2.3.4", 5)["is_tor"])
        with mock.patch.object(S, "_load_tor", fake):
            self.assertFalse(ic.src_tor_exit("9.9.9.9", 5)["is_tor"])

    def test_conf_exposes_support_oppose(self):
        c = ic._conf_bool([("proxycheck", False), ("ipapi", True)])
        self.assertIn("support", c)
        self.assertIn("oppose", c)
        self.assertTrue(c["support"])
        self.assertTrue(c["oppose"])


class TestProbe(unittest.TestCase):
    def test_classify(self):
        import ipcheck_lib.probe as P
        self.assertEqual(P.classify(204, ""), "连接成功(未验证登录/功能)")
        self.assertEqual(P.classify(200, "ok"), "连接成功(未验证登录/功能)")
        self.assertIn("地区", P.classify(403, "Country, region, or territory not supported"))
        self.assertIn("人机", P.classify(403, "Just a moment... checking your browser"))
        self.assertIn("原因不明", P.classify(403, "forbidden"))
        self.assertIn("登录", P.classify(401, ""))
        self.assertIn("连接失败", P.classify(None, ""))
        self.assertIn("地区", P.classify(451, ""))

    def test_classify_browser_not_region(self):
        import ipcheck_lib.probe as P
        v = P.classify(403, "Your browser is unsupported")
        self.assertNotEqual(v, "明确地区限制")
        self.assertIn("浏览器", v)

    def test_classify_challenge_on_200(self):
        import ipcheck_lib.probe as P
        self.assertIn("人机", P.classify(200, "Just a moment... checking your browser"))

    def test_probe_layers_dns_fail(self):
        import ipcheck_lib.probe as P
        import socket
        def boom(*a, **k):
            raise socket.gaierror(-2, "Name or service not known")
        with mock.patch.object(P.socket, "getaddrinfo", boom):
            r = P.probe_layers("https://example.test/", 5)
        self.assertEqual(r["layer"], "dns")
        self.assertIsNotNone(r["error"])

    def test_probe_data_is_json_serializable(self):
        import json
        import ipcheck_lib.cli as C
        import ipcheck_lib.probe as P
        row = {"site": "x", "verdict": "连接成功(未验证登录/功能)", "detail": "HTTP 200",
               "status": 200, "url": "u", "note": "", "layers": None}
        with mock.patch.object(P, "egress_via", lambda proxy, timeout: "1.2.3.4"), \
                mock.patch.object(P, "run_probe", lambda **k: [row]):
            d = C._probe_data("http://p:1", "1.2.3.4", None, 5)
        self.assertEqual(d["egress"], "1.2.3.4")
        self.assertEqual(d["targets"][0]["site"], "x")
        json.dumps(d)  # 不抛异常即说明可结构化

    def test_recommend_nodes(self):
        import ipcheck_lib.cli as C
        nodes = [
            {"node": "a", "region": 1, "fail": 0, "stable": True, "challenge": 0, "avg_tls_ms": 100},
            {"node": "b", "region": 0, "fail": 0, "stable": True, "challenge": 0, "avg_tls_ms": 200},
            {"node": "c", "region": 0, "fail": 0, "stable": False, "challenge": 0, "avg_tls_ms": 50},
        ]
        self.assertEqual(C._recommend_nodes(nodes), "b")  # b 稳定且无地区限制，优于不稳定的 c

    def test_generated_at_present(self):
        agg = ic.aggregate("1.2.3.4", [])
        self.assertIn("generated_at", agg)

    def test_diff_runs(self):
        import ipcheck_lib.cli as C
        prev = {"version": "1.0.0", "egress": "1.1.1.1", "targets": [{"site": "x", "verdict": "ok"}]}
        cur = {"version": "1.0.1", "egress": "2.2.2.2", "targets": [{"site": "x", "verdict": "人机验证"}]}
        txt = " ".join(C._diff_runs(prev, cur))
        self.assertIn("算法版本", txt)
        self.assertIn("出口", txt)
        self.assertIn("目标表现", txt)
        self.assertEqual(C._diff_runs(prev, prev), ["无显著变化"])

    def test_history_save_load(self):
        import os
        import tempfile
        import ipcheck_lib.cli as C
        d = tempfile.mkdtemp()
        old = os.environ.get("IPCHECK_HISTORY")
        os.environ["IPCHECK_HISTORY"] = os.path.join(d, "h.jsonl")
        try:
            C._save_history({"ts": "t1", "version": "1", "node": "direct", "scenario": "ai",
                             "egress": "1.1.1.1", "stable": True, "targets": []})
            C._save_history({"ts": "t2", "version": "1", "node": "direct", "scenario": "ai",
                             "egress": "2.2.2.2", "stable": True, "targets": []})
            h = C._load_history()
            self.assertEqual(len(h), 2)
            self.assertEqual(h[-1]["egress"], "2.2.2.2")
        finally:
            if old is None:
                os.environ.pop("IPCHECK_HISTORY", None)
            else:
                os.environ["IPCHECK_HISTORY"] = old


class TestP0Guards(unittest.TestCase):
    def test_private_ip_skips_public_query(self):
        agg = ic.check_ip("10.0.0.1")
        self.assertIn("本地", agg["ip_type"])
        self.assertEqual(agg["verdict"]["risk_level"], "unknown")
        self.assertEqual(agg["sources"], [])

    def test_spamhaus_pbl_is_not_malicious(self):
        with mock.patch.object(S, "_dns_query_a", lambda *a, **k: "127.0.0.4"):
            d = ic.src_spamhaus("1.2.3.4", 5)
        self.assertTrue(d["listed"])
        self.assertFalse(d["malicious"])
        self.assertTrue(d["policy"])

    def test_spamhaus_sbl_is_malicious(self):
        with mock.patch.object(S, "_dns_query_a", lambda *a, **k: "127.0.0.2"):
            d = ic.src_spamhaus("1.2.3.4", 5)
        self.assertTrue(d["malicious"])

    def test_vote_value_equals_confidence_value(self):
        # 主结论值与置信度值必须一致（统一判决）
        votes = [("proxycheck", True), ("iphub", False), ("ipapi", False)]
        conf = ic._conf_bool(votes)
        val = ic._vote([], "P", votes)
        self.assertEqual(val, conf["value"])

    def test_local_verdict_unknown_label(self):
        agg = ic._local_agg("192.168.1.1")
        self.assertIsNone(agg["verdict"]["risk_score"])
        self.assertEqual(agg["verdict"]["risk_level"], "unknown")

    def test_has_fields(self):
        self.assertFalse(ic._has_fields({}))
        self.assertFalse(ic._has_fields({"a": None, "b": None}))
        self.assertTrue(ic._has_fields({"proxy": False}))   # False 是有效数据
        self.assertTrue(ic._has_fields({"city": "X"}))

    def test_geo_only_is_unknown_not_residential(self):
        # 只有国家信息：不能判“住宅/干净”
        results = [{"source": "ipinfo", "ok": True,
                    "data": {"country": "US", "country_code": "US"}, "error": None}]
        agg = ic.aggregate("1.2.3.4", results)
        self.assertIn("证据不足", agg["ip_type"])
        self.assertEqual(agg["verdict"]["risk_level"], "unknown")
        self.assertEqual(agg["platform_fit"], [])

    def test_rdap_only_not_clean(self):
        results = [{"source": "rdap", "ok": True,
                    "data": {"handle": "X", "org": "ACME", "start": "1.2.3.0", "end": "1.2.3.255"},
                    "error": None}]
        agg = ic.aggregate("1.2.3.4", results)
        self.assertEqual(agg["verdict"]["risk_level"], "unknown")

    def test_detect_cloud(self):
        self.assertEqual(ic.detect_cloud("AS15169 Google LLC"), "Google")
        self.assertEqual(ic.detect_cloud("AS16509 Amazon.com, Inc."), "AWS")
        self.assertIsNone(ic.detect_cloud("Some Random ISP"))

    def test_cloud_implies_datacenter(self):
        results = [{"source": "ipinfo", "ok": True,
                    "data": {"country": "US", "country_code": "US",
                             "asn_org": "AS15169 Google LLC"}, "error": None}]
        agg = ic.aggregate("8.8.8.8", results)
        self.assertEqual(agg["network"]["cloud"], "Google")
        self.assertIn("机房", agg["ip_type"])

    def test_field_sources_applicability(self):
        # 地理字段不采用代理库；每个字段带 applicability
        results = [{"source": "ipinfo", "ok": True,
                    "data": {"country": "US", "country_code": "US", "asn_org": "AS15169 Google LLC"}, "error": None},
                   {"source": "proxycheck", "ok": True,
                    "data": {"proxy": True, "type": "VPN", "country_code": "US"}, "error": None}]
        agg = ic.aggregate("1.2.3.4", results)
        geo_src = agg["evidence"]["geo"]["sources"]
        self.assertIn("ipinfo.io", geo_src)
        self.assertNotIn("proxycheck.io", geo_src)   # 地理字段不使用代理库
        self.assertIn("数据库标签", agg["evidence"]["proxy"]["applicability"])

    def test_spamhaus_transient_is_unknown(self):
        import socket
        def again(*a, **k):
            raise socket.gaierror(-3, "Temporary failure in name resolution")
        with mock.patch.object(S, "_dns_query_a", again):
            with self.assertRaises(RuntimeError):
                ic.src_spamhaus("1.2.3.4", 5)
        def noname(*a, **k):
            raise socket.gaierror(11001, "Host not found")
        with mock.patch.object(S, "_dns_query_a", noname):
            self.assertFalse(ic.src_spamhaus("1.2.3.4", 5)["listed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
