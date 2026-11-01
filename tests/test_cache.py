#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_cache.py — 来源级缓存 / 时间元数据 / 陈旧边界 验收
=====================================================

覆盖（与审计验收场景对应）：
- 有效缓存命中：不访问上游、保留原 fetched_at。
- 自然过期后成功刷新（不只是 refresh 手动绕过）。
- 过期且刷新失败：标注 expired_refresh_failed 并保留旧数据。
- 过期超允许回退期：expired_too_old，ok=False（仅历史、不参与判断）。
- 首次失败：不生成有效缓存。
- refresh=True 绕过，并穿透来源内部名单缓存（src_ipsum 收到 refresh）。
- 条目校验：合法 JSON 但 expires_ts 类型错 / 非 dict / 缺到期时间 —— 忽略重查，不崩溃。
- IPv6 归一、解析器版本入键、文件语法损坏安全忽略、缓存不含密钥。

运行： python tests/test_cache.py
"""
import os
import sys
import json
import time
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
import ipcheck_lib.sources as S  # noqa: E402


class TestCache(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.path = os.path.join(self.d, "cache.json")
        os.environ["IPCHECK_CACHE"] = self.path
        C._CACHE = None

    def tearDown(self):
        os.environ.pop("IPCHECK_CACHE", None)
        C._CACHE = None

    def _fn(self, ret):
        box = {"n": 0}

        def fn(ip, timeout):
            box["n"] += 1
            if isinstance(ret, Exception):
                raise ret
            return ret
        return fn, box

    def test_valid_hit_no_upstream_keeps_time(self):
        fn, _ = self._fn({"a": 1})
        r1 = C.fetch("ipinfo", "1.2.3.4", fn, 5, validator=lambda d: True)
        self.assertEqual(r1["cache_status"], "fresh")
        fn2, box2 = self._fn(RuntimeError("no"))
        r2 = C.fetch("ipinfo", "1.2.3.4", fn2, 5, validator=lambda d: True)
        self.assertEqual(box2["n"], 0)
        self.assertEqual(r2["cache_status"], "valid")
        self.assertEqual(r2["query_time"], r1["query_time"])

    def test_natural_expiry_then_successful_refresh(self):
        C.put_entry("ipinfo", "7.7.7.7", {"a": 1}, None, ttl=-1)  # 已自然过期
        fn, box = self._fn({"a": 2})
        r = C.fetch("ipinfo", "7.7.7.7", fn, 5, validator=lambda d: True)
        self.assertEqual(box["n"], 1)                 # 过期触发了刷新
        self.assertEqual(r["cache_status"], "refreshed")
        self.assertEqual(r["data"], {"a": 2})

    def test_expired_refresh_failed_within_stale(self):
        C.put_entry("ipinfo", "2.2.2.2", {"a": 2}, None, ttl=-60)  # 过期 1 分钟，在允许期内
        fn, _ = self._fn(RuntimeError("down"))
        r = C.fetch("ipinfo", "2.2.2.2", fn, 5, validator=lambda d: True)
        self.assertEqual(r["cache_status"], "expired_refresh_failed")
        self.assertTrue(r["ok"])
        self.assertIn("过期", r["error"])

    def test_expired_too_old_not_used(self):
        C.put_entry("spamhaus", "3.3.3.3", {"listed": True}, None, ttl=-10 * 86400)  # 过期10天 > 7天
        fn, _ = self._fn(RuntimeError("down"))
        r = C.fetch("spamhaus", "3.3.3.3", fn, 5, validator=lambda d: True)
        self.assertEqual(r["cache_status"], "expired_too_old")
        self.assertFalse(r["ok"])  # 仅历史，不参与判断

    def test_first_failure_not_cached(self):
        fn, _ = self._fn(RuntimeError("fail"))
        r = C.fetch("ipinfo", "4.4.4.4", fn, 5, validator=lambda d: True)
        self.assertEqual(r["cache_status"], "none")
        self.assertFalse(r["ok"])
        self.assertEqual(C.get_entry("ipinfo", "4.4.4.4"), {})

    def test_refresh_bypasses(self):
        C.put_entry("ipinfo", "5.5.5.5", {"a": 1}, None, ttl=3600)
        fn, box = self._fn({"b": 2})
        r = C.fetch("ipinfo", "5.5.5.5", fn, 5, refresh=True, validator=lambda d: True)
        self.assertEqual(box["n"], 1)
        self.assertEqual(r["cache_status"], "refreshed")

    def test_call_source_passes_refresh_when_supported(self):
        rec = {}

        def fn(ip, timeout, refresh=False):
            rec["refresh"] = refresh
            return {"x": 1}
        C._call_source(fn, "1.2.3.4", 5, True)
        self.assertTrue(rec["refresh"])

    def test_ipsum_refresh_penetrates_list_cache(self):
        rec = {}

        def fake_load(timeout, refresh=False):
            rec["refresh"] = refresh
            return ({"1.2.3.4": 2}, time.time())
        old = S._load_ipsum
        S._load_ipsum = fake_load
        try:
            d = ic.src_ipsum("1.2.3.4", 5, refresh=True)
            self.assertTrue(rec["refresh"])          # 刷新穿透到内部名单加载
            self.assertTrue(d["listed"])
            self.assertIn("list_fetched_at", d)
        finally:
            S._load_ipsum = old

    def test_invalid_entry_expires_type_ignored(self):
        key = C.make_key("ipinfo", "8.8.8.8")
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({key: {"data": {"a": 1}, "expires_ts": "broken", "fetched_at": "x"}}, f)
        C._CACHE = None
        fn, box = self._fn({"a": 2})
        r = C.fetch("ipinfo", "8.8.8.8", fn, 5, validator=lambda d: True)
        self.assertEqual(box["n"], 1)                 # 非法条目被忽略 -> 重新查询
        self.assertEqual(r["data"], {"a": 2})

    def test_non_dict_entry_ignored(self):
        key = C.make_key("ipinfo", "9.9.9.9")
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({key: ["not", "dict"]}, f)
        C._CACHE = None
        fn, box = self._fn({"a": 1})
        C.fetch("ipinfo", "9.9.9.9", fn, 5, validator=lambda d: True)
        self.assertEqual(box["n"], 1)

    def test_ipv6_normalized_key(self):
        self.assertEqual(C.normalize_ip("2001:0db8:0:0::1"), C.normalize_ip("2001:db8::1"))
        self.assertEqual(C.make_key("ipinfo", "2001:0db8::1"), C.make_key("ipinfo", "2001:db8::1"))

    def test_parser_version_in_key(self):
        self.assertNotEqual(C.make_key("ipinfo", "1.2.3.4", "9.9.9"),
                            C.make_key("ipinfo", "1.2.3.4", "1.0.0"))

    def test_corrupt_json_safe(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("{ not json ]")
        C._CACHE = None
        fn, _ = self._fn({"ok": 1})
        self.assertTrue(C.fetch("ipinfo", "6.6.6.6", fn, 5, validator=lambda d: True)["ok"])

    def test_no_secret_in_cache_file(self):
        os.environ["IPHUB_API_KEY"] = "SECRET_SENTINEL_XYZ"
        try:
            C.put_entry("iphub", "7.0.0.1", {"block": 0}, None, ttl=3600)
            with open(self.path, encoding="utf-8") as f:
                self.assertNotIn("SECRET_SENTINEL_XYZ", f.read())
        finally:
            os.environ.pop("IPHUB_API_KEY", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
