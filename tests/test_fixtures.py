#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_fixtures.py — 基于离线固定样本的解析回归
=============================================

用 scripts/ipcheck_lib/fixtures/ 下保存的真实响应快照，验证各源 parser 的字段映射，
不依赖线上接口每次返回一致。运行：python tests/test_fixtures.py
"""
import os
import sys
import json
import unittest
import importlib.util
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
FIX = os.path.join(ROOT, "scripts", "ipcheck_lib", "fixtures")

spec = importlib.util.spec_from_file_location("ic", os.path.join(ROOT, "scripts", "ipcheck.py"))
ic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ic)
import ipcheck_lib.sources as S  # noqa: E402


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return f.read()


def fake(text):
    def _f(url, headers=None, timeout=None, retries=1):
        return 200, text
    return _f


class TestFixtures(unittest.TestCase):
    def test_ipapi(self):
        with mock.patch.object(S, "http_get", fake(load("ipapi.json"))):
            d = ic.src_ipapi("8.8.8.8", 5)
        self.assertEqual((d["country_code"], d["city"], d["hosting"]), ("US", "Mountain View", True))

    def test_proxycheck(self):
        with mock.patch.object(S, "http_get", fake(load("proxycheck.json"))):
            d = ic.src_proxycheck("8.8.8.8", 5)
        self.assertEqual((d["proxy"], d["type"]), (False, "Business"))

    def test_stopforumspam(self):
        with mock.patch.object(S, "http_get", fake(load("stopforumspam.json"))):
            d = ic.src_stopforumspam("8.8.8.8", 5)
        self.assertEqual(d["frequency"], 0)

    def test_blocklistde(self):
        with mock.patch.object(S, "http_get", fake(load("blocklistde.json"))):
            d = ic.src_blocklistde("8.8.8.8", 5)
        self.assertEqual(d["attacks"], 0)

    def test_dbip(self):
        with mock.patch.object(S, "http_get", fake(load("dbip.json"))):
            d = ic.src_dbip("8.8.8.8", 5)
        self.assertEqual((d["country_code"], d["city"]), ("US", "Mountain View"))

    def test_rdap(self):
        with mock.patch.object(S, "http_get", fake(load("rdap.json"))):
            d = ic.src_rdap("8.8.8.8", 5)
        self.assertEqual(d["org"], "Google LLC")
        self.assertEqual(d["handle"], "NET-8-8-8-0-2")

    def test_ripe_bgp(self):
        with mock.patch.object(S, "http_get", fake(load("ripe_bgp.json"))):
            d = ic.src_ripe_bgp("8.8.8.8", 5)
        self.assertTrue(d["announced"])
        self.assertEqual(d["origin_asn"], 15169)

    def test_scamalytics_html(self):
        with mock.patch.object(S, "http_get", fake(load("scamalytics.html"))), \
                mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SCAMALYTICS_USER", None)
            os.environ.pop("SCAMALYTICS_KEY", None)
            d = ic.src_scamalytics("8.8.8.8", 5)
        self.assertEqual((d["fraud_score"], d["risk"]), (12, "Low"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
