# -*- coding: utf-8 -*-
# 由 tools/make_pkg.py 从 ipcheck.py 自动拆分生成，请勿手改结构注释。
import argparse
import concurrent.futures as cf
import csv
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from ipcheck_lib.constants import *  # noqa: F401,F403
from ipcheck_lib.http import *  # noqa: F401,F403
from ipcheck_lib.sources import *  # noqa: F401,F403
from ipcheck_lib.scoring import *  # noqa: F401,F403
from ipcheck_lib.render import *  # noqa: F401,F403
from ipcheck_lib.env import *  # noqa: F401,F403
from ipcheck_lib.csvio import *  # noqa: F401,F403
from ipcheck_lib import sources as _sources  # noqa: F401
from ipcheck_lib import probe as _probe  # noqa: F401

def _setup_console():
    """Windows 控制台默认 GBK，遇到 emoji/中文会 UnicodeEncodeError。
    启动时切 UTF-8 代码页并重配 stdout/stderr，保证任何终端都不崩。"""
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

def cmd_myip(args):
    ip, via = get_egress_ip(args.timeout)
    if not ip:
        print("无法获取出口 IP（所有回显源均失败）")
        return 2
    geo = {}
    try:
        _, txt = http_get("http://ip-api.com/json/%s?fields=status,message,country,countryCode,city,timezone,lat,lon,isp"
                          % ip, timeout=args.timeout, retries=0)
        d = _j(txt)
        if d.get("status") == "success":
            geo = {"country": d.get("country"), "country_code": d.get("countryCode"),
                   "city": d.get("city"), "timezone": d.get("timezone"),
                   "lat": d.get("lat"), "lon": d.get("lon"), "isp": d.get("isp")}
    except Exception:
        pass
    env = env_consistency(geo)
    if args.json:
        print(json.dumps({"egress_ip": ip, "via": via, "geo": geo, "env": env},
                         ensure_ascii=False, indent=2, default=str))
    else:
        print("当前出口 IP: " + ip + "   (来源: " + str(via) + ")")
        if geo.get("country"):
            print("位置: %s %s   ISP: %s   时区: %s" % (
                geo.get("country"), geo.get("city") or "", geo.get("isp") or "", geo.get("timezone") or ""))
        print(render_env(env))
    return 0

def cmd_open(args):
    """一键打开网页并自动带上 IP（用于人工核验被 Cloudflare 拦的站点）。"""
    import webbrowser
    from ipaddress import ip_address
    try:
        ip_address(args.ip)
    except ValueError:
        print("非法 IP: " + args.ip, file=sys.stderr)
        return 2
    urls = {
        "abuseipdb": "https://www.abuseipdb.com/check/%s" % args.ip,
        "iphub": "https://iphub.info/?ip=%s" % args.ip,
        "scamalytics": "https://scamalytics.com/ip/%s" % args.ip,
        "stopforumspam": "https://www.stopforumspam.com/search?q=%s" % args.ip,
    }
    if args.all:
        which = list(urls)
    elif args.which:
        which = [x.strip() for x in args.which.split(",") if x.strip()]
        bad = [x for x in which if x not in urls]
        if bad:
            print("未知站点: %s（可选: %s）" % (",".join(bad), ",".join(urls)), file=sys.stderr)
            return 2
    else:
        which = ["abuseipdb"]
    for name in which:
        u = urls[name]
        print("打开 %-14s %s" % (name, u))
        try:
            webbrowser.open(u)
        except Exception as e:  # noqa: BLE001
            print("  打不开浏览器，请手动访问上面的链接（%s）" % e, file=sys.stderr)
    return 0

def cmd_stability(args):
    color = not args.no_color and sys.stdout.isatty()
    c = C(color)

    if args.interactive:
        print(c.b("[第 1 步] 采样当前出口 IP ..."))
        ip1, via1 = get_egress_ip(args.timeout)
        if not ip1:
            print("无法获取出口 IP"); return 2
        print("  当前出口 IP: " + c.cyan(ip1) + "  (来源 " + str(via1) + ")")
        print("\n现在请执行：断开当前网络 / 切换节点 / 重连代理，然后回到这里。")
        try:
            input("完成后按回车继续 ...")
        except EOFError:
            pass
        print(c.b("\n[第 2 步] 重连后再次采样 ..."))
        ip2, via2 = get_egress_ip(args.timeout)
        if not ip2:
            print("无法获取出口 IP"); return 2
        print("  重连后 IP: " + c.cyan(ip2) + "  (来源 " + str(via2) + ")")

        stable = (ip1 == ip2)
        print("-" * 60)
        if stable:
            print(c.green("稳定性结论: 稳定 —— 断开重连前后出口 IP 一致 (%s)" % ip1))
        else:
            print(c.yellow("稳定性结论: 已变更 —— %s  ->  %s" % (ip1, ip2)))
        print("-" * 60)
        print(c.b("\n对重连后的 IP 做完整信誉检测："))
        agg = check_ip(ip2, only=args.only, timeout=args.timeout)
        print(render_report(agg, color=color))
        if args.json:
            print(render_json(agg))
        return 0

    # 非交互：连续采样
    ips = []
    print(c.b("连续采样出口 IP：%d 轮，间隔 %ds" % (args.rounds, args.interval)))
    for i in range(args.rounds):
        ip, via = get_egress_ip(args.timeout)
        ts = time.strftime("%H:%M:%S")
        if ip:
            ips.append(ip)
            print("  [%s] #%d  %s" % (ts, i + 1, ip))
        else:
            print("  [%s] #%d  采样失败" % (ts, i + 1))
        if i < args.rounds - 1:
            time.sleep(args.interval)
    uniq = sorted(set(ips))
    print("-" * 60)
    if len(uniq) == 1:
        print(c.green("稳定性结论: 稳定 —— 全部 %d 次采样均为 %s" % (len(ips), uniq[0])))
    elif len(uniq) == 0:
        print(c.red("稳定性结论: 全部采样失败"))
    else:
        print(c.yellow("稳定性结论: 漂移 —— 出现 %d 个不同出口 IP: %s" % (len(uniq), ", ".join(uniq))))
    if args.json:
        print(json.dumps({"samples": ips, "unique": uniq}, ensure_ascii=False, indent=2))
    return 0

def _parse_only(s):
    if not s:
        return None
    names = [x.strip() for x in re.split(r"[,\s]+", s) if x.strip()]
    bad = [n for n in names if n not in _sources.SOURCES]
    if bad:
        raise argparse.ArgumentTypeError("未知数据源: %s（可选: %s）"
                                         % (",".join(bad), ",".join(_sources.ALL_SOURCES)))
    return names

def gateway_check(ip, base, token=None, timeout=30):
    """通过自建网关查询（客户端无需任何源 key）。"""
    url = base.rstrip("/") + "/check?ip=" + urllib.parse.quote(ip)
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    status, txt = http_get(url, headers=headers, timeout=timeout, retries=0)
    return _j(txt)

def cmd_check(args):
    color = not args.no_color and sys.stdout.isatty()
    from ipaddress import ip_address
    gw = (args.gateway or os.environ.get("IPCHECK_GATEWAY", "").strip() or None)
    gw_token = os.environ.get("IPCHECK_GATEWAY_TOKEN", "").strip() or None
    ips = list(args.ips or [])
    if getattr(args, "file", None):
        try:
            with open(args.file, "r", encoding="utf-8-sig") as f:
                for line in f:
                    line = line.split("#")[0].strip()
                    if line:
                        ips.append(line)
        except Exception as e:  # noqa: BLE001
            print("读取 --file 失败: %s" % e, file=sys.stderr)
            return 2
    if not ips:
        print("请提供 IP（直接给参数，或用 --file 列出）", file=sys.stderr)
        return 2
    csv_rows = []
    rc = 0
    for idx, ip in enumerate(ips):
        if idx > 0 and getattr(args, "interval", 0):
            time.sleep(args.interval)
        try:
            ip_address(ip)
        except ValueError:
            print("跳过非法 IP: " + ip, file=sys.stderr)
            rc = 2
            continue
        if gw:
            try:
                agg = gateway_check(ip, gw, gw_token, timeout=max(args.timeout, 30))
            except Exception as e:  # noqa: BLE001
                print("网关查询失败(%s): %s" % (gw, e), file=sys.stderr)
                rc = 2
                continue
        else:
            agg = check_ip(ip, only=args.only, timeout=args.timeout)
        if getattr(args, "env", False):
            try:
                agg["env"] = env_consistency(agg.get("geo") or {})
            except Exception:
                agg["env"] = {}
        if getattr(args, "regions", False):
            try:
                agg["regions"] = compute_regions(agg.get("geo") or {})
            except Exception:
                agg["regions"] = None
        probe_d = None
        if getattr(args, "probe", False):
            probe_d = _probe_data(
                getattr(args, "proxy", None) or os.environ.get("IPCHECK_PROXY", "").strip() or None,
                ip, None, args.timeout)
            agg["probe"] = probe_d  # 结构化进 JSON，不污染 stdout
        csv_rows.append(_agg_to_row(agg))
        if args.json:
            print(render_json(agg))
        elif getattr(args, "brief", False):
            print(render_brief(agg))
        else:
            if idx:
                print()
            print(render_report(agg, color=color))
            if agg.get("env"):
                print(render_env(agg["env"]))
            if not getattr(args, "no_platforms", False):
                extra = render_platforms(agg)
                if extra:
                    print(extra)
            if agg.get("regions"):
                print(render_regions(agg["regions"]))
            if probe_d:
                print()
                _render_probe(probe_d)
        if getattr(args, "open", False):
            import webbrowser
            for u in ("https://www.abuseipdb.com/check/%s" % ip,
                      "https://iphub.info/?ip=%s" % ip):
                try:
                    webbrowser.open(u)
                except Exception:
                    pass
            print("已打开 abuseipdb / iphub 网页（IP 已带入，可人工核验）")
    if getattr(args, "csv", None):
        try:
            write_csv(csv_rows, args.csv)
            print("已导出 CSV: %s（%d 行）" % (args.csv, len(csv_rows)), file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            print("导出 CSV 失败: %s" % e, file=sys.stderr)
            rc = 2
    return rc

def cmd_watch(args):
    """轮询监控：目标 IP 关键属性变化，或监控自身出口 IP 漂移。"""
    color = not args.no_color and sys.stdout.isatty()
    c = C(color)
    from ipaddress import ip_address
    light = args.only or ["ipinfo", "ipapi", "proxycheck", "spamhaus"]

    def snap(agg):
        fl, vd, sc = agg["flags"], agg["verdict"], agg["scores"]
        return {
            "ip_type": agg.get("ip_type"),
            "proxy": fl.get("proxy"), "vpn": fl.get("vpn"),
            "hosting": fl.get("hosting"),
            "risk": vd.get("risk_score"),
            "spamhaus": sc.get("spamhaus_listed"),
        }

    def diff(old, new):
        ch = []
        for k in ("ip_type", "proxy", "vpn", "hosting", "risk", "spamhaus"):
            if old.get(k) != new.get(k):
                ch.append("%s: %s -> %s" % (k, old.get(k), new.get(k)))
        return ch

    print(c.b("监控开始：间隔 %ds，%s（Ctrl+C 停止）" %
              (args.interval, "出口 IP 漂移" if args.egress else "目标 IP 变化")))
    prev = {}
    prev_egress = None
    rounds = args.rounds or 10**9
    try:
        for r in range(rounds):
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            if args.egress:
                ip, via = get_egress_ip(args.timeout)
                if not ip:
                    print("[%s] 采样失败" % ts)
                elif prev_egress is None:
                    prev_egress = ip
                    print("[%s] 出口 IP: %s" % (ts, ip))
                elif ip != prev_egress:
                    print(c.yellow("[%s] ⚠️ 出口 IP 漂移: %s -> %s" % (ts, prev_egress, ip)))
                    prev_egress = ip
                else:
                    print(c.dim("[%s] 出口 IP 稳定: %s" % (ts, ip)))
            else:
                for ip in args.ips:
                    try:
                        ip_address(ip)
                    except ValueError:
                        continue
                    agg = check_ip(ip, only=light, timeout=args.timeout)
                    cur = snap(agg)
                    if ip in prev:
                        ch = diff(prev[ip], cur)
                        if ch:
                            print(c.yellow("[%s] ⚠️ %s 变化: %s" % (ts, ip, "; ".join(ch))))
                        else:
                            print(c.dim("[%s] %s 无变化 (risk=%s)" % (ts, ip, cur.get("risk"))))
                    else:
                        print("[%s] %s 基线: type=%s risk=%s" % (ts, ip, cur.get("ip_type"), cur.get("risk")))
                    prev[ip] = cur
            if r < rounds - 1:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n监控已停止")
    return 0

_PROBE_SCEN = {
    "general": None,
    "browse": ["google", "x", "tiktok"],
    "ai": ["openai", "anthropic", "chatgpt"],
    "stream": ["netflix"],
    "account": ["google", "x"],
    "call": ["google"],
}


def _probe_data(proxy, expect_ip, only, timeout):
    egress = _probe.egress_via(proxy, timeout) if proxy else get_egress_ip(timeout)[0]
    guard = None
    if expect_ip and egress and expect_ip != egress:
        guard = "出口(%s) ≠ 目标(%s)，实测结论只归因于 %s" % (egress, expect_ip, egress)
    rows = _probe.run_probe(proxy=proxy, only=only, timeout=timeout)
    return {"mode": "proxy" if proxy else "direct", "egress": egress, "guard": guard, "targets": rows}


def _render_probe(d):
    print("实测出口 IP: %s（%s）" % (d.get("egress") or "未知",
                                "经代理" if d.get("mode") == "proxy" else "本机直连"))
    if d.get("guard"):
        print("⚠️ " + d["guard"])
    print("站点              状态                            详情")
    for r in d.get("targets", []):
        print("  %-12s %-28s %s" % (r["site"], r["verdict"], r["detail"]))
    print("说明: 200≠功能可用；403≠封号；401 可能只是没带 key；未登录/未付费，仅只读探测。")


def cmd_probe(args):
    only = [x.strip() for x in args.only.split(",") if x.strip()] if args.only else None
    d = _probe_data(args.proxy, args.expect_ip, only, args.timeout)
    if getattr(args, "json", False):
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        _render_probe(d)
    return 0


def cmd_node(args):
    """面向用途的节点体检：出口一致性/短时稳定性 + 场景目标实测 + 与证据匹配的建议。"""
    proxy = args.proxy or os.environ.get("IPCHECK_PROXY", "").strip() or None
    scen = args.scenario or "general"
    only = _PROBE_SCEN.get(scen)
    samples = max(1, args.samples)
    egress_list = []
    for i in range(samples):
        e = _probe.egress_via(proxy, args.timeout) if proxy else get_egress_ip(args.timeout)[0]
        egress_list.append(e)
        if i < samples - 1:
            time.sleep(args.interval)
    uniq = sorted({x for x in egress_list if x})
    stable = bool(egress_list) and all(egress_list) and len(uniq) == 1
    egress = egress_list[0] if egress_list else None
    guard = None
    if args.expect_ip and egress and egress != args.expect_ip:
        guard = "出口(%s) ≠ 目标(%s)" % (egress, args.expect_ip)
    rows = _probe.run_probe(proxy=proxy, only=only, timeout=args.timeout)

    bad_region = [r for r in rows if "地区限制" in r["verdict"]]
    challenge = [r for r in rows if "人机" in r["verdict"]]
    fail = [r for r in rows if "连接失败" in r["verdict"]]
    advice = []
    if not stable:
        advice.append("出口在短时采样中变化（%s）：长期账号/支付前应先解决出口稳定性。" % (",".join(uniq) or "未知"))
    if bad_region:
        advice.append("端点报告地区限制（%s）：当前出口不适合该端点。" % ",".join(r["site"] for r in bad_region))
    if challenge:
        advice.append("遇到人机验证（≠封号，%s）：可换出口或降低频率。" % ",".join(r["site"] for r in challenge))
    if fail and not bad_region:
        advice.append("部分目标连接失败（%s）：检查节点连通性。" % ",".join(r["site"] for r in fail))
    if not advice:
        advice.append("已测目标可达（未验证登录/业务功能）；短时结果不代表长期稳定。")

    data = {"scenario": scen, "mode": "proxy" if proxy else "direct", "egress": egress,
            "egress_samples": egress_list, "stable": stable, "guard": guard,
            "targets": rows, "advice": advice}
    if getattr(args, "json", False):
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0
    print("节点体检（场景：%s）" % scen)
    print("出口: %s（%s，%d 次采样 %s）" % (
        egress or "未知", "经代理" if proxy else "本机直连", samples,
        "稳定" if stable else "有变化: " + (",".join(uniq) or "未知")))
    if guard:
        print("⚠️ %s —— 实测只归因于实际出口" % guard)
    print("场景目标:")
    for r in rows:
        print("  %-12s %-28s %s" % (r["site"], r["verdict"], r["detail"]))
    print("建议:")
    for a in advice:
        print("  - " + a)
    print("说明: 短时实测，不等于长期表现；不预测封号/账号安全。")
    return 0


def cmd_health(args):
    """逐源健康检查：探测每个源是否可用及延迟（上游失效/限流的显式降级）。"""
    ip = args.ip or "8.8.8.8"
    names = [n for n in (args.only or _sources.ALL_SOURCES) if n in _sources.SOURCES]

    def one(n):
        t0 = time.time()
        try:
            _sources.SOURCES[n](ip, args.timeout)
            return (n, True, int((time.time() - t0) * 1000), "")
        except Exception as e:  # noqa: BLE001
            return (n, False, int((time.time() - t0) * 1000), str(e)[:90])

    rows = {}
    with cf.ThreadPoolExecutor(max_workers=min(len(names), 10) or 1) as ex:
        for r in ex.map(one, names):
            rows[r[0]] = r
    print("源健康检查 (探针 IP=%s, 超时=%.0fs)" % (ip, args.timeout))
    print("  %-18s %-6s %-7s %s" % ("源", "状态", "耗时", "错误"))
    okn = 0
    for n in names:
        _, ok, ms, err = rows[n]
        okn += 1 if ok else 0
        print("  %-18s %-6s %-7s %s" % (n, "OK" if ok else "FAIL", "%dms" % ms, err))
    print("正常 %d/%d（FAIL 的源在检测中会自动跳过并标注，不会影响其它源）" % (okn, len(names)))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="ipcheck",
        description="多源 IP 信誉检测（ipinfo / ip-api / ipwho.is / proxycheck / scamalytics / iphub / abuseipdb）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  ipcheck check 8.8.8.8\n"
               "  ipcheck 8.8.8.8 --brief\n"
               "  ipcheck 8.8.8.8 --open          # 同时打开 abuseipdb/iphub 网页(带IP)\n"
               "  ipcheck open 8.8.8.8 --all      # 只打开网页人工核验\n"
               "  ipcheck myip\n"
               "  ipcheck stability --rounds 5 --interval 3\n"
               "  ipcheck stability --interactive\n")
    p.add_argument("--version", action="version", version="ipcheck " + VERSION)
    sub = p.add_subparsers(dest="cmd")

    pc = sub.add_parser("check", help="检测一个或多个 IP")
    pc.add_argument("ips", nargs="*", help="要检测的 IP（可多个；也可用 --file）")
    pc.add_argument("--file", default=None, help="从文件读 IP（每行一个，# 注释）")
    pc.add_argument("--csv", default=None, help="把结果导出 CSV")
    pc.add_argument("--only", type=_parse_only, default=None,
                    help="只用这些源，逗号分隔: " + ",".join(_sources.ALL_SOURCES))
    pc.add_argument("--json", action="store_true", help="输出 JSON")
    pc.add_argument("--brief", action="store_true", help="一行式简报")
    pc.add_argument("--open", action="store_true", help="检测后自动打开 abuseipdb/iphub 网页(IP已带入)")
    pc.add_argument("--env", action="store_true", help="附加环境一致性检测（本机时区/DNS vs IP，防关联指纹）")
    pc.add_argument("--platforms", action="store_true", help="(兼容保留) 站点适配度现已默认显示")
    pc.add_argument("--no-platforms", action="store_true", help="不显示站点适配度")
    pc.add_argument("--regions", action="store_true", help="追加各服务在 IP 所在国的可用性(OpenAI/Netflix/PayPal 等)")
    pc.add_argument("--probe", action="store_true", help="追加实测：从出口(或 --proxy)真实访问各站点(只读)")
    pc.add_argument("--proxy", default=None, help="实测经此 HTTP 代理出口，如 http://host:port")
    pc.add_argument("--gateway", default=None,
                    help="走自建网关（也可用环境变量 IPCHECK_GATEWAY），客户端无需任何源 key")
    pc.add_argument("--interval", type=float, default=0.0,
                    help="批量时每个 IP 之间的间隔秒（防免费源限流）")
    pc.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    pc.add_argument("--no-color", action="store_true")
    pc.set_defaults(func=cmd_check)

    po = sub.add_parser("open", help="打开网页并自动填入 IP（人工核验用）")
    po.add_argument("ip")
    po.add_argument("--all", action="store_true", help="打开全部站点")
    po.add_argument("--which", default=None,
                    help="指定站点，逗号分隔: abuseipdb,iphub,scamalytics,stopforumspam")
    po.set_defaults(func=cmd_open)

    pm = sub.add_parser("myip", help="查看当前出口 IP")
    pm.add_argument("--json", action="store_true")
    pm.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    pm.add_argument("--no-color", action="store_true")
    pm.set_defaults(func=cmd_myip)

    ps = sub.add_parser("stability", help="出口 IP 稳定性检测")
    ps.add_argument("--rounds", type=int, default=3, help="采样轮数（非交互）")
    ps.add_argument("--interval", type=int, default=5, help="采样间隔秒（非交互）")
    ps.add_argument("--interactive", action="store_true", help="断开/重连前后对比")
    ps.add_argument("--only", type=_parse_only, default=None, help="完整检测时使用的源")
    ps.add_argument("--json", action="store_true")
    ps.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ps.add_argument("--no-color", action="store_true")
    ps.set_defaults(func=cmd_stability)

    pw = sub.add_parser("watch", help="轮询监控：目标 IP 变化 / 出口 IP 漂移")
    pw.add_argument("ips", nargs="*", help="要监控的 IP（--egress 时不需要）")
    pw.add_argument("--egress", action="store_true", help="监控自身出口 IP 是否漂移")
    pw.add_argument("--interval", type=int, default=60, help="轮询间隔秒")
    pw.add_argument("--rounds", type=int, default=0, help="轮询轮数，0=直到 Ctrl+C")
    pw.add_argument("--only", type=_parse_only, default=None, help="监控使用的源（默认轻量集）")
    pw.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    pw.add_argument("--no-color", action="store_true")
    pw.set_defaults(func=cmd_watch)

    pp = sub.add_parser("probe", help="实测：从出口/代理只读访问各站点，给出分层可用性状态")
    pp.add_argument("--proxy", default=None, help="经此 HTTP 代理出口，如 http://host:port")
    pp.add_argument("--expect-ip", default=None, help="期望出口 IP；若实际出口不符会告警")
    pp.add_argument("--only", default=None, help="只测这些站点，逗号分隔: " + ",".join(_probe.TARGETS))
    pp.add_argument("--timeout", type=float, default=10)
    pp.add_argument("--no-color", action="store_true")
    pp.add_argument("--json", action="store_true", help="输出结构化 JSON（不混排版文本）")
    pp.set_defaults(func=cmd_probe)

    pn = sub.add_parser("node", help="面向用途的节点体检：出口一致性/稳定性 + 场景目标实测 + 建议")
    pn.add_argument("--proxy", default=None, help="经此 HTTP 代理出口，如 http://host:port")
    pn.add_argument("--expect-ip", default=None, help="期望出口 IP；不符会告警")
    pn.add_argument("--scenario", default="general",
                    choices=list(_PROBE_SCEN), help="用途场景")
    pn.add_argument("--samples", type=int, default=3, help="出口采样次数")
    pn.add_argument("--interval", type=int, default=2, help="采样间隔秒")
    pn.add_argument("--timeout", type=float, default=10)
    pn.add_argument("--json", action="store_true")
    pn.set_defaults(func=cmd_node)

    ph = sub.add_parser("health", help="源健康检查：逐源探测可用性/延迟（上游失效显式降级）")
    ph.add_argument("--ip", default="8.8.8.8", help="探针 IP")
    ph.add_argument("--only", type=_parse_only, default=None, help="只检查这些源")
    ph.add_argument("--timeout", type=float, default=8)
    ph.set_defaults(func=cmd_health)
    return p

def main(argv=None):
    _setup_console()
    argv = argv if argv is not None else sys.argv[1:]
    # 简化：允许 `ipcheck.py 8.8.8.8` 或 `ipcheck.py --file x.txt`（等价于 check）
    if argv and argv[0] not in ("check", "myip", "stability", "open", "watch", "probe", "node", "health",
                                "-h", "--help", "--version", "-V"):
        argv = ["check"] + argv
    p = build_parser()
    if not argv:
        p.print_help()
        return 0
    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        p.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n已中断", file=sys.stderr)
        return 130


__all__ = ['_setup_console', 'cmd_myip', 'cmd_open', 'cmd_stability', '_parse_only', 'gateway_check', 'cmd_check', 'cmd_watch', 'build_parser', 'main']
