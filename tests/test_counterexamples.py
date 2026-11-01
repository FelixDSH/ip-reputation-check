#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_counterexamples.py — 用"之前的反例"回测当前版本（可复现，非读测试名）
=========================================================================

覆盖此前审计逐个指出的失败场景，作为硬性回归：
- 全空结果 -> 无法判定（非干净）
- 只有地理（ipinfo 国家+ASN 但无信誉来源）-> 类型可能机房但**信誉未知**、无平台建议
- 只有 RDAP -> 无法判定
- DB-IP 返回全 null -> 视为无有效数据
- DNSBL EAI_AGAIN（临时失败）-> 未知（非未上榜）；NXDOMAIN -> 未上榜
- 探针 403 "browser unsupported" -> 非地区限制；200 挑战页 -> 人机验证
- 结构化 probe 可 JSON 序列化

运行： python tests/test_counterexamples.py
"""
import os
import sys
import json
import socket
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
import ipcheck_lib.cli as C  # noqa: E402


class Counterexamples(unittest.TestCase):
    def test_all_empty_is_unknown(self):
        agg = ic.aggregate("1.2.3.4", [])
        self.assertEqual(agg["verdict"]["risk_level"], "unknown")
        self.assertIn("数据不足", agg["ip_type"])

    def test_geo_and_asn_but_no_reputation_is_not_clean(self):
        # 地理+ASN 成功（足以判机房），但没有任何信誉/滥用来源 -> 信誉必须未知、无平台建议
        results = [{"source": "ipinfo", "ok": True,
                    "data": {"country": "US", "country_code": "US", "asn_org": "AS15169 Google LLC"},
                    "error": None}]
        agg = ic.aggregate("8.8.8.8", results)
        self.assertIn("机房", agg["ip_type"])                 # 类型可由云厂商证据判定
        self.assertEqual(agg["verdict"]["risk_level"], "unknown")  # 但信誉未知，不判干净
        self.assertEqual(agg["platform_fit"], [])             # 无平台"绿色"建议
        self.assertEqual(agg["confidence"]["abuse"]["level"], "unknown")

    def test_only_rdap_is_unknown(self):
        results = [{"source": "rdap", "ok": True,
                    "data": {"handle": "NET", "org": "ACME", "start": "1.2.3.0", "end": "1.2.3.255"},
                    "error": None}]
        agg = ic.aggregate("1.2.3.4", results)
        self.assertEqual(agg["verdict"]["risk_level"], "unknown")

    def test_dbip_empty_fields_is_no_data(self):
        self.assertFalse(ic._has_fields({"country": None, "country_code": None, "city": None}))

    def test_dns_transient_unknown_vs_nxdomain_notlisted(self):
        def again(*a, **k):
            raise socket.gaierror(-3, "Temporary failure in name resolution")
        with mock.patch.object(S, "_dns_query_a", again):
            with self.assertRaises(RuntimeError):
                ic.src_spamhaus("1.2.3.4", 5)
        def nx(*a, **k):
            raise socket.gaierror(11001, "Host not found")
        with mock.patch.object(S, "_dns_query_a", nx):
            self.assertFalse(ic.src_spamhaus("1.2.3.4", 5)["listed"])

    def test_probe_region_and_challenge(self):
        self.assertNotEqual(P.classify(403, "Your browser is unsupported"), "明确地区限制")
        self.assertIn("人机", P.classify(200, "Just a moment... checking your browser"))
        self.assertEqual(P.classify(401, ""), "需登录/鉴权(匿名无法验证)")
        self.assertIn("原因不明", P.classify(403, "forbidden"))

    def test_structured_probe_json(self):
        row = {"site": "x", "verdict": "连接成功(未验证登录/功能)", "detail": "HTTP 200",
               "status": 200, "url": "u", "note": "", "layers": None}
        with mock.patch.object(P, "egress_via", lambda proxy, timeout: "1.2.3.4"), \
                mock.patch.object(P, "run_probe", lambda **k: [row]):
            d = C._probe_data("http://p:1", "1.2.3.4", None, 5)
        json.dumps(d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
