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
            with mock.patch.object(S, "http_get", fake("<html>oops</html>")):
                with self.assertRaises(RuntimeError):
                    S._load_ipsum(5, refresh=True)
        finally:
            S._IPSUM_DATA = old

    def test_ipsum_valid(self):
        old = S._IPSUM_DATA
        S._IPSUM_DATA = None
        try:
            with mock.patch.object(S, "http_get", fake("# header\n1.2.3.4\t5\n5.6.7.8\t2\n")):
                d, ts = S._load_ipsum(5, refresh=True)
            self.assertEqual(d.get("1.2.3.4"), 5)
        finally:
            S._IPSUM_DATA = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
