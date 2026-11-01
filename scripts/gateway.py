#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gateway.py — 多人/团队共用的 IP 检测网关（把 key 藏在服务端，客户端无需任何 key）
================================================================================

为什么需要它：
  API Key 绑定的是「你账号」的配额。把 key 写进分发给很多人的 skill → 大家共用你一份额度，
  很快被限流/封禁，也不安全。正确做法是：**一台服务端持有 key + 缓存 + 限流**，
  其他人只访问这台网关（免 key），网关负责去重与保护配额。

架构：
  客户端(任意 ipcheck)  --HTTP-->  本网关(持有 IPHUB_API_KEY/ABUSEIPDB_API_KEY + 缓存)  -->  各情报源

特性：
  - 服务端持有 key（环境变量），客户端不需要任何 key
  - 内存 TTL 缓存：同 IP 在 TTL 内只真正查询一次，极大节省免费额度
  - 简单限流：每客户端 IP 每分钟 N 次
  - 可选访问令牌 GATEWAY_TOKEN

用法：
  export IPHUB_API_KEY=xxx          # 服务端配一次即可
  export ABUSEIPDB_API_KEY=xxx
  python gateway.py --host 0.0.0.0 --port 8787 --ttl 300 --rate 60 --token SECRET

客户端：
  set IPCHECK_GATEWAY=http://网关IP:8787
  set IPCHECK_GATEWAY_TOKEN=SECRET
  python ipcheck.py check 8.8.8.8   # 自动走网关，无需任何源 key

接口：
  GET /check?ip=8.8.8.8        -> 聚合 JSON（与 ipcheck --json 同结构）
  GET /health                  -> {"ok":true}
"""
import argparse
import json
import os
import sys
import time
import threading
import ipaddress
import hmac
from collections import OrderedDict, defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ipcheck  # noqa: E402

_lock = threading.Lock()
_cache = OrderedDict()   # ip -> (expire_ts, agg_dict)，带 LRU 上限
CACHE_MAX = 5000
_rate = defaultdict(deque)  # client_ip -> deque[timestamps]
RATE_WINDOW = 60.0


def _get_cached(cache_key, ttl):
    with _lock:
        item = _cache.get(cache_key)
        if item and item[0] > time.time():
            _cache.move_to_end(cache_key)
            return item[1]
        if item:
            _cache.pop(cache_key, None)   # 过期清除
    return None


def _set_cached(cache_key, agg, ttl):
    with _lock:
        _cache[cache_key] = (time.time() + ttl, agg)
        _cache.move_to_end(cache_key)
        # 清理过期 + 超上限淘汰最旧
        now = time.time()
        for k in [k for k, v in list(_cache.items()) if v[0] <= now]:
            _cache.pop(k, None)
        while len(_cache) > CACHE_MAX:
            _cache.popitem(last=False)


def _rate_ok(client_ip, limit):
    if limit <= 0:
        return True
    now = time.time()
    with _lock:
        dq = _rate[client_ip]
        while dq and now - dq[0] > RATE_WINDOW:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True


class Handler(BaseHTTPRequestHandler):
    server_version = "ipcheck-gateway/1.0"
    gateway_token = None
    ttl = 300
    rate = 60
    trust_xff = False

    def _token_eq(self, a, b):
        try:
            return hmac.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))
        except Exception:
            return False

    def _send(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def _client_key(self):
        if self.trust_xff:
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()
        return self.client_address[0]

    def _authorized(self, qs):
        if not self.gateway_token:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and self._token_eq(auth[7:].strip(), self.gateway_token):
            return True
        if self._token_eq(qs.get("token", [None])[0], self.gateway_token):
            return True
        return False

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/health":
            return self._send(200, {"ok": True})
        if u.path != "/check":
            return self._send(404, {"error": "not found"})
        if not self._authorized(qs):
            return self._send(401, {"error": "unauthorized"})

        ip = (qs.get("ip", [""])[0] or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return self._send(400, {"error": "invalid ip"})

        client_ip = self._client_key()
        if not _rate_ok(client_ip, self.rate):
            return self._send(429, {"error": "rate limit exceeded, retry later"})

        cache_key = ip
        agg = _get_cached(cache_key, self.ttl)
        cached = agg is not None
        if agg is None:
            try:
                agg = ipcheck.check_ip(ip)
            except Exception as e:  # noqa: BLE001
                return self._send(502, {"error": "upstream failed: %s" % e})
            _set_cached(cache_key, agg, self.ttl)

        payload = dict(agg)
        payload["_gateway"] = {"cached": cached, "ttl": self.ttl}
        return self._send(200, payload)

    def log_message(self, fmt, *args):
        sys.stderr.write("[gw %s] %s\n" % (self.address_string(), fmt % args))


def main():
    ap = argparse.ArgumentParser(description="IP 检测共享网关（服务端持 key，客户端免 key）")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--ttl", type=int, default=300, help="缓存秒数")
    ap.add_argument("--rate", type=int, default=60, help="每客户端 IP 每分钟次数，0=不限")
    ap.add_argument("--token", default=os.environ.get("GATEWAY_TOKEN", "").strip(),
                    help="访问令牌（也可用环境变量 GATEWAY_TOKEN）")
    ap.add_argument("--only", default=None, help="固定使用这些源，逗号分隔")
    ap.add_argument("--trust-proxy", action="store_true",
                    help="信任反向代理的 X-Forwarded-For 作为限流键（反代后面开启）")
    args = ap.parse_args()

    if args.only:
        ipcheck.ALL_SOURCES = [x.strip() for x in args.only.split(",") if x.strip()]

    Handler.gateway_token = args.token or None
    Handler.ttl = args.ttl
    Handler.rate = args.rate
    Handler.trust_xff = args.trust_proxy

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    keys = [k for k in ("IPHUB_API_KEY", "ABUSEIPDB_API_KEY", "IPINFO_TOKEN") if os.environ.get(k)]
    print("ipcheck-gateway 监听 http://%s:%d" % (args.host, args.port))
    print("  TTL=%ss  rate=%s/min  token=%s  服务端已配 key: %s"
          % (args.ttl, args.rate, "有" if args.token else "无", ", ".join(keys) or "无（仍可免 key 跑基础源）"))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n停止")
        srv.shutdown()


if __name__ == "__main__":
    main()
