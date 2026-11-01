#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_contract.py — 上游契约检测：异常页面/名单不得解析成功
=========================================================

覆盖（对应审计建议）：验证码页、错误页、字段缺失、分数越界 -> 解析失败（不猜）；
Tor/IPsum 名单遇 HTML/空/有效项过少 -> 报错，不当名单。不承诺能发现所有改版。

运行： python tests/test_contract.py
"""
import os
import sys
import unittest
import importlib.util
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
spec = importlib.util.spec_from_file_location("ic", os.path.join(ROOT, "scripts", "ipcheck.py"))
ic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ic)
import ipcheck_lib.sources as S  # noqa: E402
import ipcheck_lib.probe as P  # noqa: E402

FIX = os.path.join(ROOT, "scripts", "ipcheck_lib", "fixtures", "abnormal")
FIX_ROOT = os.path.join(ROOT, "scripts", "ipcheck_lib", "fixtures")


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return f.read()


def load_root(name):
    with open(os.path.join(FIX_ROOT, name), encoding="utf-8") as f:
        return f.read()


def fake(text):
    def _f(url, headers=None, timeout=None, retries=1):
        return 200, text
    return _f


class TestScamalyticsContract(unittest.TestCase):
    def test_valid_page(self):
        html = "<html><body><div>Fraud Score: 12</div><span>Low Risk</span></body></html>"
        d = ic.parse_scamalytics_html(html, "8.8.8.8")
        self.assertEqual((d["fraud_score"], d["risk"]), (12, "Low"))

    def test_captcha_page(self):
        for html in ("<html><body>Just a moment... checking your browser</body></html>",
                     "<html><body>Please verify you are human / captcha</body></html>"):
            with self.assertRaises(RuntimeError):
                ic.parse_scamalytics_html(html, "1.2.3.4")

    def test_error_page(self):
        for html in ("<html><body>Access denied</body></html>",
                     "<html><body>403 Forbidden</body></html>"):
            with self.assertRaises(RuntimeError):
                ic.parse_scamalytics_html(html, "1.2.3.4")

    def test_missing_score(self):
        with self.assertRaises(RuntimeError):
            ic.parse_scamalytics_html("<html><body><span>Low Risk</span></body></html>", "1.2.3.4")

    def test_score_out_of_range(self):
        with self.assertRaises(RuntimeError):
            ic.parse_scamalytics_html("<html><body>Fraud Score: 999</body></html>", "1.2.3.4")

    def test_empty(self):
        with self.assertRaises(RuntimeError):
            ic.parse_scamalytics_html("", "1.2.3.4")

    # 真实形态 fixture
    def test_fixture_captcha(self):
        with self.assertRaises(RuntimeError):
            ic.parse_scamalytics_html(load("scamalytics_captcha.html"), "1.2.3.4")

    def test_fixture_softblock_200(self):
        # HTTP 200 但软封/地区页，即使含 "Fraud Score: 0" 诱饵，也必须拒绝
        with self.assertRaises(RuntimeError):
            ic.parse_scamalytics_html(load("scamalytics_softblock_200.html"), "1.2.3.4")

    def test_fixture_valid_full_still_parses(self):
        d = ic.parse_scamalytics_html(load("scamalytics_valid_full.html"), "8.8.8.8")
        self.assertEqual(d["fraud_score"], 0)
        self.assertEqual(d["risk"], "Low")


class TestListContract(unittest.TestCase):
    def test_tor_html_page_rejected(self):
        old = S._TOR_DATA
        S._TOR_DATA = None
        try:
            with mock.patch.object(S, "http_get", fake("<html><body>error</body></html>")):
                with self.assertRaises(RuntimeError):
                    S._load_tor(5, refresh=True)
        finally:
            S._TOR_DATA = old

    def test_tor_too_few_rejected(self):
        old = S._TOR_DATA
        S._TOR_DATA = None
        try:
            with mock.patch.object(S, "http_get", fake("1.2.3.4\n5.6.7.8\n")):
                with self.assertRaises(RuntimeError):
                    S._load_tor(5, refresh=True)
        finally:
            S._TOR_DATA = old

    def test_tor_valid_list(self):
        old = S._TOR_DATA
        S._TOR_DATA = None
        body = "\n".join("10.0.%d.%d" % (i // 256, i % 256) for i in range(100))
        try:
            with mock.patch.object(S, "http_get", fake(body)):
                s, ts = S._load_tor(5, refresh=True)
            self.assertGreaterEqual(len(s), 50)
        finally:
            S._TOR_DATA = old

    def test_ipsum_html_rejected(self):
        old = S._IPSUM_DATA
        S._IPSUM_DATA = None
        try:
            with mock.patch.object(S, "http_get", fake(load("ipsum_error.html"))):
                with self.assertRaises(RuntimeError):
                    S._load_ipsum(5, refresh=True)
        finally:
            S._IPSUM_DATA = old

    def test_tor_error_fixture_rejected(self):
        old = S._TOR_DATA
        S._TOR_DATA = None
        try:
            with mock.patch.object(S, "http_get", fake(load("tor_error.html"))):
                with self.assertRaises(RuntimeError):
                    S._load_tor(5, refresh=True)
        finally:
            S._TOR_DATA = old

    def test_ipsum_valid(self):
        old = S._IPSUM_DATA
        S._IPSUM_DATA = None
        try:
            with mock.patch.object(S, "http_get", fake("# header\n1.2.3.4\t5\n5.6.7.8\t2\n")):
                d, ts = S._load_ipsum(5, refresh=True)
            self.assertEqual(d.get("1.2.3.4"), 5)
        finally:
            S._IPSUM_DATA = old


class TestProbeSoftblock(unittest.TestCase):
    def test_200_softblock_region_is_not_success(self):
        # HTTP 200 + 地区软封文案，不能判"连接成功"
        self.assertEqual(P.classify(200, "This service is not available in your region"),
                         "明确地区限制")

    def test_200_challenge_is_human_verification(self):
        self.assertIn("人机", P.classify(200, "Just a moment... checking your browser"))


class TestRdapBgpContract(unittest.TestCase):
    def test_rdap_error_empty_norange_wrongrange(self):
        for fn in ("rdap_error.json", "rdap_empty.json", "rdap_no_range.json", "rdap_wrong_range.json"):
            with mock.patch.object(S, "http_get", fake(load(fn))):
                with self.assertRaises(RuntimeError):
                    ic.src_rdap("8.8.8.8", 5)

    def test_rdap_valid(self):
        with mock.patch.object(S, "http_get", fake(load_root("rdap.json"))):
            d = ic.src_rdap("8.8.8.8", 5)
        self.assertEqual(d["handle"], "NET-8-8-8-0-2")
        self.assertTrue(d["range_covers"])

    def test_bgp_error_noasn_wrongprefix(self):
        for fn in ("bgp_error.json", "bgp_no_asn.json", "bgp_wrong_prefix.json"):
            with mock.patch.object(S, "http_get", fake(load(fn))):
                with self.assertRaises(RuntimeError):
                    ic.src_ripe_bgp("8.8.8.8", 5)

    def test_bgp_valid_keeps_origin(self):
        with mock.patch.object(S, "http_get", fake(load_root("ripe_bgp.json"))):
            d = ic.src_ripe_bgp("8.8.8.8", 5)
        self.assertTrue(d["announced"])
        self.assertEqual(d["origin_asn"], 15169)
        self.assertEqual(len(d["asns"]), 1)


class TestJsonSourceContracts(unittest.TestCase):
    def test_proxycheck_empty_node(self):
        with mock.patch.object(S, "http_get", fake('{"status":"ok"}')):
            with self.assertRaises(RuntimeError):
                ic.src_proxycheck("1.2.3.4", 5)

    def test_sfp_failure_and_missing_ip(self):
        for body in ('{"success":0}', '{"success":1}'):
            with mock.patch.object(S, "http_get", fake(body)):
                with self.assertRaises(RuntimeError):
                    ic.src_stopforumspam("1.2.3.4", 5)

    def test_blocklistde_missing_fields(self):
        with mock.patch.object(S, "http_get", fake('{"foo":1}')):
            with self.assertRaises(RuntimeError):
                ic.src_blocklistde("1.2.3.4", 5)

    def test_dbip_missing_geo(self):
        with mock.patch.object(S, "http_get", fake('{}')):
            with self.assertRaises(RuntimeError):
                ic.src_dbip("1.2.3.4", 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
