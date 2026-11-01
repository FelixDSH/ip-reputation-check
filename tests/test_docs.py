#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_docs.py — 文档漂移回归
==========================

防止 README 里残留旧版示例/旧措辞、与当前输出不一致。
无网络，仅文本检查。

运行： python tests/test_docs.py
"""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 旧版残留/易误导措辞（不应出现在 README 正文）
BANNED = ["综合判定", "易被风控", "5 个免 key", "坐标"]


class TestDocs(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            self.readme = f.read()
        with open(os.path.join(ROOT, "examples", "demo.txt"), encoding="utf-8") as f:
            self.demo = f.read()

    def test_no_banned_stale_terms(self):
        for b in BANNED:
            self.assertNotIn(b, self.readme, "README 含旧版残留措辞: " + b)

    def test_current_terms_present(self):
        self.assertIn("规则提示分", self.readme)
        self.assertIn("examples/demo.txt", self.readme)

    def test_no_duplicate_h2(self):
        heads = re.findall(r"^## (.+)$", self.readme, re.M)
        dup = [h for h in set(heads) if heads.count(h) > 1]
        self.assertEqual(dup, [], "README 存在重复二级标题: %s" % dup)

    def test_demo_matches_current_format(self):
        # 权威示例 demo.txt 必须含当前所有关键区块，防止再次漂移
        for marker in ("规则提示分", "字段来源", "证据强度", "登记(RDAP)", "路由(BGP)", "易触发风控"):
            self.assertIn(marker, self.demo, "demo.txt 缺少当前格式标记: " + marker)

    def test_readme_points_to_demo(self):
        self.assertIn("examples/demo.txt", self.readme)


if __name__ == "__main__":
    unittest.main(verbosity=2)
