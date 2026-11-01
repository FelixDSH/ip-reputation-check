#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selfcheck.py — 一键自检（离线测试 + 在线冒烟）
=============================================

用途：改完代码后自行验证，不必手动逐个跑测试。
  - 离线：运行 tests/ 下全部测试（不需要网络稳定）。
  - 在线：对一个公开 IP 做最小真实查询（ipinfo/ipapi），验证调用链/解析仍工作；
          私有地址本地判定；JSON 可序列化。
  - 任一失败 -> 退出码 1。

用法：
  python scripts/selfcheck.py            # 离线 + 在线
  python scripts/selfcheck.py --offline  # 仅离线（CI/无网）
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TESTS = ["test_core.py", "test_cache.py", "test_counterexamples.py",
         "test_fixtures.py", "test_contract.py", "test_docs.py", "test_consistency.py"]


def run_tests():
    fails = []
    for t in TESTS:
        path = os.path.join(ROOT, "tests", t)
        r = subprocess.run([sys.executable, path], capture_output=True, text=True)
        ok = r.returncode == 0
        print(("[PASS] " if ok else "[FAIL] ") + t)
        if not ok:
            fails.append(t)
            sys.stderr.write((r.stderr or r.stdout)[-800:])
    return fails


def live_smoke():
    sys.path.insert(0, HERE)
    import ipcheck
    problems = []
    # 私有地址本地判定
    a = ipcheck.check_ip("10.0.0.1")
    if "本地" not in (a.get("ip_type") or ""):
        problems.append("私有地址未本地判定")
    # JSON 可序列化
    try:
        json.dumps(a)
    except Exception:
        problems.append("聚合结果不可 JSON 序列化")
    # 在线最小查询
    try:
        agg = ipcheck.check_ip("8.8.8.8", only=["ipinfo", "ipapi"], refresh=True)
        if not (agg.get("geo") or {}).get("country"):
            problems.append("在线查询未取到国家（可能无网）")
        json.dumps(agg)
    except Exception as e:  # noqa: BLE001
        problems.append("在线查询异常: %s" % e)
    return problems


def main():
    offline = "--offline" in sys.argv
    print("== selfcheck ==")
    fails = run_tests()
    problems = []
    if not offline:
        print("-- live smoke --")
        problems = live_smoke()
        if problems:
            for p in problems:
                print("[FAIL] " + p)
        else:
            print("[PASS] live smoke (8.8.8.8 minimal query, private local, JSON)")
    else:
        print("(offline: 跳过在线冒烟)")
    ok = not fails and not problems
    print("== RESULT: %s ==" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
