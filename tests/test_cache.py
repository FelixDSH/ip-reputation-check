#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_cache.py — 来源级缓存 / 时间元数据验收
==========================================

对应审计验收场景：有效缓存不访问上游且保留原查询时间、过期刷新、过期且刷新失败标注、
首次失败不生成"有效未命中"、解析器版本变化键不同、refresh 绕过、IPv6 归一、文件损坏安全忽略、不含密钥。

运行： python tests/test_cache.py
"""
import os
import sys
import tempfile
import unittest
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
spec = importlib.util.spec_from_file_location("ic", os.path.join(ROOT, "scripts", "ipcheck.py"))
ic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ic)
import ipcheck_lib.cache as C  # noqa: E402


class TestCache(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.path = os.path.join(self.d, "cache.json")
        os.environ["IPCHECK_CACHE"] = self.path
        C._CACHE = None  # 强制从新路径加载

    def tearDown(self):
        os.environ.pop("IPCHECK_CACHE", None)
        C._CACHE = None

    def _counter_fn(self, ret):
        box = {"n": 0}

        def fn(ip, timeout):
            box["n"] += 1
            if isinstance(ret, Exception):
                raise ret
            return ret
        return fn, box

    def test_valid_cache_no_upstream_and_keeps_time(self):
        fn, box = self._counter_fn({"a": 1})
        r1 = C.fetch("ipinfo", "1.2.3.4", fn, 5, validator=lambda d: True)
        self.assertEqual(r1["cache_status"], "fresh")
        fn2, box2 = self._counter_fn(RuntimeError("should not call"))
        r2 = C.fetch("ipinfo", "1.2.3.4", fn2, 5, validator=lambda d: True)
        self.assertEqual(box2["n"], 0)                       # 命中缓存，不访问上游
        self.assertEqual(r2["cache_status"], "valid")
        self.assertEqual(r2["query_time"], r1["query_time"])  # 保留原取得时间，不改写
        self.assertEqual(r2["data"], {"a": 1})

    def test_valid_hit_does_not_call_upstream(self):
        fn, box = self._counter_fn({"a": 1})
        C.fetch("ipinfo", "9.9.9.9", fn, 5, validator=lambda d: True)
        fn2, box2 = self._counter_fn(RuntimeError("should not call"))
        r = C.fetch("ipinfo", "9.9.9.9", fn2, 5, validator=lambda d: True)
        self.assertEqual(box2["n"], 0)   # 未访问上游
        self.assertEqual(r["cache_status"], "valid")
        self.assertEqual(r["data"], {"a": 1})

    def test_expired_refresh_failed_marks_stale(self):
        C.put_entry("ipinfo", "2.2.2.2", {"a": 2}, None, ttl=-1)  # 立即过期
        fn, box = self._counter_fn(RuntimeError("upstream down"))
        r = C.fetch("ipinfo", "2.2.2.2", fn, 5, validator=lambda d: True)
        self.assertEqual(r["cache_status"], "expired_refresh_failed")
        self.assertEqual(r["data"], {"a": 2})
        self.assertIn("过期", r["error"])

    def test_first_failure_not_cached(self):
        fn, box = self._counter_fn(RuntimeError("fail"))
        r = C.fetch("ipinfo", "3.3.3.3", fn, 5, validator=lambda d: True)
        self.assertEqual(r["cache_status"], "none")
        self.assertFalse(r["ok"])
        self.assertEqual(C.get_entry("ipinfo", "3.3.3.3"), {})  # 未生成缓存

    def test_refresh_bypasses(self):
        C.put_entry("ipinfo", "4.4.4.4", {"a": 1}, None, ttl=3600)
        fn, box = self._counter_fn({"b": 2})
        r = C.fetch("ipinfo", "4.4.4.4", fn, 5, refresh=True, validator=lambda d: True)
        self.assertEqual(box["n"], 1)  # 强制刷新，访问上游
        self.assertEqual(r["data"], {"b": 2})
        self.assertEqual(r["cache_status"], "refreshed")

    def test_ipv6_normalized_key(self):
        self.assertEqual(C.normalize_ip("2001:0db8:0:0::1"), C.normalize_ip("2001:db8::1"))
        self.assertEqual(C.make_key("ipinfo", "2001:0db8::1"), C.make_key("ipinfo", "2001:db8::1"))

    def test_parser_version_in_key(self):
        self.assertNotEqual(C.make_key("ipinfo", "1.2.3.4", "9.9.9"),
                            C.make_key("ipinfo", "1.2.3.4", "1.0.0"))

    def test_corrupt_cache_safe(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("{ not json ]")
        C._CACHE = None
        fn, box = self._counter_fn({"ok": 1})
        r = C.fetch("ipdb", "5.5.5.5", fn, 5, validator=lambda d: True)
        self.assertTrue(r["ok"])

    def test_no_secret_in_cache_file(self):
        os.environ["IPHUB_API_KEY"] = "SECRET_SENTINEL_XYZ"
        try:
            C.put_entry("iphub", "6.6.6.6", {"block": 0}, None, ttl=3600)
            with open(self.path, encoding="utf-8") as f:
                txt = f.read()
            self.assertNotIn("SECRET_SENTINEL_XYZ", txt)
        finally:
            os.environ.pop("IPHUB_API_KEY", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
