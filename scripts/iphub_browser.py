#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iphub_browser.py — iphub 游客接口「人工过验证」兜底
====================================================

当 iphub 游客接口（https://iphub.info/api/lookup/ip）返回
`{"success":false,"error":"Human verification required","captchaRequired":true}`
时，用真实 Chrome 打开页面：你在弹出的浏览器里点一下 Cloudflare Turnstile 的勾选/完成验证，
脚本会自动捕获结果并打印 JSON。

依赖：playwright（`pip install playwright`） + 本机已安装 Chrome。
不使用 headless，以便完成人机验证。

用法：
  python iphub_browser.py 8.8.8.8
  python iphub_browser.py 8.8.8.8 --timeout 240
"""
import argparse
import json
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ip")
    ap.add_argument("--timeout", type=int, default=180, help="等待人工验证的秒数")
    args = ap.parse_args()

    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print("需要 playwright：pip install playwright  (原始错误: %s)" % e)
        return 3

    result = {}

    def on_resp(r):
        if "/api/lookup/ip" in r.url:
            try:
                b = r.text()
                if '"success":true' in b.replace(" ", ""):
                    result["body"] = b
            except Exception:
                pass

    with sync_playwright() as p:
        browser = p.chromium.launch(
            channel="chrome", headless=False,
            args=["--disable-blink-features=AutomationControlled"])
        ctx = browser.new_context(
            user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"),
            locale="en-US", viewport={"width": 1366, "height": 860})
        page = ctx.new_page()
        page.on("response", on_resp)

        print("打开 iphub ... 若出现『人机验证』，请在浏览器窗口里完成勾选。")
        try:
            page.goto("https://iphub.info/?ip=%s" % args.ip,
                      wait_until="domcontentloaded", timeout=45000)
        except Exception:
            pass

        # 先自动填入并点击一次 Lookup
        page.wait_for_timeout(2500)
        try:
            page.fill("#lookupInput", args.ip)
            page.click("button[type=submit]")
        except Exception:
            pass

        deadline = time.time() + args.timeout
        while time.time() < deadline and "body" not in result:
            # 轮询页面里的 JSON 展示区
            try:
                txt = page.inner_text("#lookupJson")
                if "{" in txt and '"error"' not in txt:
                    result["body"] = txt
                    break
            except Exception:
                pass
            page.wait_for_timeout(1000)

        browser.close()

    body = result.get("body")
    if not body:
        print("未取到结果（可能未在限定时间内完成验证）。可增大 --timeout 后重试。")
        return 2
    # 尽量净化成合法 JSON 输出
    try:
        print(json.dumps(json.loads(body), ensure_ascii=False, indent=2))
    except Exception:
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
