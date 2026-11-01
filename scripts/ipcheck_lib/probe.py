# -*- coding: utf-8 -*-
"""probe.py — 真实连通性/可用性探针（P2）。

原则：
- 只从「当前出口」或「用户指定 HTTP 代理」发少量、只读请求；不登录、不注册、不付费、不批量重试。
- 严格区分「实测结果」与「规则推测」；HTTP 200≠功能可用，403≠封号，401 可能只是没带 key。
- 判定只看 status + 少量正文关键词，不猜测名单语义。
"""
import concurrent.futures as cf
import ssl
import urllib.error
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

_REGION_MARKERS = ("not supported", "unsupported", "not available in your",
                   "country, region", "region or territory", "not available in this")
_CHALLENGE_MARKERS = ("just a moment", "challenge-platform", "cf-chl", "attention required",
                      "verify you are human", "cf-turnstile", "checking your browser")


def _opener(proxy=None):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    return urllib.request.build_opener(*handlers)


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
    if status == 204 or 200 <= status < 300:
        return "连接成功(未验证登录/功能)"
    if status in (301, 302, 303, 307, 308):
        return "连接成功(重定向)"
    if status == 401:
        return "需登录/鉴权(匿名无法验证)"
    if status == 429:
        return "限流(稍后重试)"
    if status == 451:
        return "法律/地区限制"
    if status == 403:
        if any(k in low for k in _REGION_MARKERS):
            return "明确地区限制"
        if any(k in low for k in _CHALLENGE_MARKERS):
            return "人机验证(挑战页,不等于封号)"
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
        st, body, err = probe_http(cfg["url"], proxy=proxy, timeout=timeout)
        return {"site": name, "url": cfg["url"], "note": cfg.get("note", ""),
                "status": st, "verdict": classify(st, body),
                "detail": (("HTTP %s" % st) if st is not None else ("ERR: " + (err or "")))[:80]}

    with cf.ThreadPoolExecutor(max_workers=min(workers, max(1, len(names)))) as ex:
        for r in ex.map(one, names):
            out.append(r)
    return out


__all__ = ["TARGETS", "probe_http", "classify", "egress_via", "run_probe"]
