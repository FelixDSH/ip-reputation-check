# -*- coding: utf-8 -*-
"""probe.py — 真实连通性/可用性探针（P2）。

原则：
- 只从「当前出口」或「用户指定 HTTP 代理」发少量、只读请求；不登录、不注册、不付费、不批量重试。
- 严格区分「实测结果」与「规则推测」；HTTP 200≠功能可用，403≠封号，401 可能只是没带 key。
- 判定只看 status + 少量正文关键词，不猜测名单语义。
"""
import concurrent.futures as cf
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"

# 目标站点（只读首页 / 探测端点）
TARGETS = {
    "google":   {"url": "https://www.google.com/generate_204", "note": "连通性(204)"},
    "openai":   {"url": "https://api.openai.com/v1/models", "note": "OpenAI 地区/鉴权"},
    "anthropic": {"url": "https://api.anthropic.com/v1/models", "note": "Claude 地区/鉴权"},
    "chatgpt":  {"url": "https://chatgpt.com/", "note": "ChatGPT 网页"},
    "x":        {"url": "https://x.com/", "note": "X/Twitter"},
    "tiktok":   {"url": "https://www.tiktok.com/", "note": "TikTok"},
    "telegram": {"url": "https://web.telegram.org/", "note": "Telegram"},
    "paypal":   {"url": "https://www.paypal.com/", "note": "PayPal"},
    "binance":  {"url": "https://www.binance.com/", "note": "Binance"},
    "netflix":  {"url": "https://www.netflix.com/", "note": "Netflix"},
}

_REGION_MARKERS = ("not supported in your country", "not available in your country",
                   "not available in your region", "not supported in your region",
                   "unsupported country", "country, region, or territory",
                   "region or territory not", "not available in this country",
                   "地区不受支持", "所在地区不可用", "not available in your location")
_CHALLENGE_MARKERS = ("just a moment", "challenge-platform", "cf-chl", "attention required",
                      "verify you are human", "cf-turnstile", "checking your browser",
                      "enable javascript and cookies to continue")
_BROWSER_MARKERS = ("browser is unsupported", "unsupported browser", "browser version",
                    "update your browser", "浏览器不受支持")


def _opener(proxy=None):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    return urllib.request.build_opener(*handlers)


def _host_port(url):
    u = urllib.parse.urlparse(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    return host, port, u.scheme


def probe_layers(url, timeout=10):
    """直连模式下分层测量 DNS / TCP / TLS。返回 {dns_ms,tcp_ms,tls_ms,layer,error}。"""
    host, port, scheme = _host_port(url)
    res = {"dns_ms": None, "tcp_ms": None, "tls_ms": None, "layer": None, "error": None}
    try:
        t = time.time()
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        res["dns_ms"] = int((time.time() - t) * 1000)
        af, st, proto, _cn, addr = infos[0]
    except Exception as e:  # noqa: BLE001
        res["layer"] = "dns"; res["error"] = str(e)
        return res
    try:
        t = time.time()
        s = socket.socket(af, st, proto)
        s.settimeout(timeout)
        s.connect(addr)
        res["tcp_ms"] = int((time.time() - t) * 1000)
    except Exception as e:  # noqa: BLE001
        res["layer"] = "tcp"; res["error"] = str(e)
        return res
    if scheme == "https":
        try:
            t = time.time()
            ss = ssl.create_default_context().wrap_socket(s, server_hostname=host)
            res["tls_ms"] = int((time.time() - t) * 1000)
            ss.close()
        except Exception as e:  # noqa: BLE001
            res["layer"] = "tls"; res["error"] = str(e)
            try:
                s.close()
            except Exception:
                pass
            return res
    else:
        s.close()
    return res


_LAYER_CN = {"dns": "DNS解析", "tcp": "TCP连接", "tls": "TLS握手"}


def probe_http(url, proxy=None, timeout=10, method="GET"):
    """返回 (status|None, body_snippet, error|None)。仅读前 4KB。"""
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": UA, "Accept": "text/html,application/json,*/*"})
    try:
        with _opener(proxy).open(req, timeout=timeout) as r:
            return r.status, r.read(4096).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4096).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body, None
    except Exception as e:  # noqa: BLE001
        reason = getattr(e, "reason", None) or e
        return None, "", str(reason)


def classify(status, body=""):
    """把一次 HTTP 结果分类为可用性状态（纯函数，可单测）。"""
    if status is None:
        return "连接失败(网络/DNS/TLS)"
    low = (body or "").lower()
    # 挑战页可能在 200 / 403 / 503，优先识别
    if any(k in low for k in _CHALLENGE_MARKERS):
        return "人机验证(挑战页,不等于封号)"
    if status == 451:
        return "法律/地区限制"
    if any(k in low for k in _REGION_MARKERS):
        return "明确地区限制"
    if any(k in low for k in _BROWSER_MARKERS):
        return "客户端/浏览器不受支持(非地区限制)"
    if status == 204 or 200 <= status < 300:
        return "连接成功(未验证登录/功能)"
    if status in (301, 302, 303, 307, 308):
        return "连接成功(重定向)"
    if status == 401:
        return "需登录/鉴权(匿名无法验证)"
    if status == 429:
        return "限流(稍后重试)"
    if status == 403:
        return "访问拒绝(原因不明,不能断定封IP)"
    if status >= 500:
        return "目标服务端错误(HTTP %d)" % status
    return "请求被拒(HTTP %d)" % status


def egress_via(proxy, timeout=10):
    """经指定代理获取公网出口 IP。"""
    status, body, _ = probe_http("https://icanhazip.com", proxy=proxy, timeout=timeout)
    if status == 200 and body.strip():
        return body.strip().splitlines()[0].strip()
    return None


def run_probe(proxy=None, only=None, timeout=10, workers=8):
    """并发探测目标站点，返回 [{site,note,status,verdict,detail}]。"""
    names = [n for n in (only or list(TARGETS)) if n in TARGETS]
    out = []

    def one(name):
        cfg = TARGETS[name]
        layers = None
        if not proxy:  # 直连模式才做逐层分解；代理模式由代理完成握手
            layers = probe_layers(cfg["url"], timeout)
            if layers.get("layer"):
                v = "连接失败(%s)" % _LAYER_CN.get(layers["layer"], layers["layer"])
                return {"site": name, "url": cfg["url"], "note": cfg.get("note", ""),
                        "status": None, "verdict": v,
                        "detail": (layers["layer"] + "失败: " + (layers.get("error") or ""))[:90],
                        "layers": layers}
        st, body, err = probe_http(cfg["url"], proxy=proxy, timeout=timeout)
        parts = []
        if layers:
            parts.append("DNS %sms/TCP %sms/TLS %sms" % (
                layers.get("dns_ms"), layers.get("tcp_ms"), layers.get("tls_ms")))
        parts.append("HTTP %s" % st if st is not None else ("ERR " + (err or "")))
        return {"site": name, "url": cfg["url"], "note": cfg.get("note", ""),
                "status": st, "verdict": classify(st, body),
                "detail": " · ".join(parts)[:110], "layers": layers}

    with cf.ThreadPoolExecutor(max_workers=min(workers, max(1, len(names)))) as ex:
        for r in ex.map(one, names):
            out.append(r)
    return out


__all__ = ["TARGETS", "probe_http", "probe_layers", "classify", "egress_via", "run_probe"]
