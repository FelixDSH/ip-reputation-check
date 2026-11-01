#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setup_geoip.py — 一键下载 MaxMind GeoLite2 本地库（免费，需 MaxMind 账号 License Key）
======================================================================================

MaxMind GeoLite2 是最权威的免费地理库，但需要：
  1) 注册免费 MaxMind 账号 → 生成 License Key
  2) 本脚本用 key 下载 .mmdb 到 data/ 目录
  3) 查询依赖 maxminddb（pip install maxminddb）

注册/获取 key： https://www.maxmind.com/en/geolite2/signup  →  My Account → Manage License Keys

用法：
  python scripts/setup_geoip.py --license-key YOUR_KEY
  set MAXMIND_LICENSE_KEY=YOUR_KEY & python scripts/setup_geoip.py
可选：
  --edition GeoLite2-City（默认，含城市） 或 GeoLite2-Country（更小）
  --out data（默认仓库 data/ 目录）

下载后 ipcheck 会自动在 data/ 下发现 .mmdb 并使用；也可用环境变量 GEOIP2_MMDB 指定路径。
"""
import argparse
import io
import os
import sys
import tarfile
import urllib.parse
import urllib.request

UA = "ipcheck-setup/1.0"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--license-key", default=os.environ.get("MAXMIND_LICENSE_KEY", "").strip())
    ap.add_argument("--edition", default="GeoLite2-City",
                    choices=["GeoLite2-City", "GeoLite2-Country"])
    ap.add_argument("--out", default=os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")))
    args = ap.parse_args()

    if not args.license_key:
        print("缺少 License Key。请到 https://www.maxmind.com/en/geolite2/signup 注册获取，"
              "然后 --license-key YOUR_KEY 或设 MAXMIND_LICENSE_KEY。")
        return 2

    qs = urllib.parse.urlencode({
        "edition_id": args.edition, "license_key": args.license_key,
        "suffix": "tar.gz",
    })
    url = "https://download.maxmind.com/app/geoip_download?" + qs
    print("[1/3] 下载 %s ..." % args.edition)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
    except Exception as e:  # noqa: BLE001
        print("下载失败：%s\n（检查 License Key 是否正确、是否有 %s 权限）" % (e, args.edition))
        return 1
    print("      下载 %.1f MB" % (len(data) / 1048576))

    print("[2/3] 解压 .mmdb -> %s" % args.out)
    os.makedirs(args.out, exist_ok=True)
    found = None
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar.getmembers():
            if m.name.endswith(".mmdb"):
                f = tar.extractfile(m)
                if not f:
                    continue
                dst = os.path.join(args.out, os.path.basename(m.name))
                with open(dst, "wb") as out:
                    out.write(f.read())
                found = dst
                break
    if not found:
        print("压缩包里没找到 .mmdb")
        return 1
    print("      已保存: %s" % found)

    print("[3/3] 检查查询库 maxminddb ...")
    try:
        import maxminddb  # noqa: F401
        print("      maxminddb 已安装 ✓")
    except Exception:
        print("      未安装，请执行:  pip install maxminddb")

    print("\n完成。ipcheck 会自动使用 %s；也可 set GEOIP2_MMDB=%s" % (found, found))
    return 0


if __name__ == "__main__":
    sys.exit(main())
