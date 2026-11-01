# -*- coding: utf-8 -*-
"""cache.py — 来源级结果缓存（只缓存各来源原始结果，不缓存最终判断）。

要点（对应审计规格）：
- 缓存键 = 解析器版本 + 来源 + 规范化 IP（IPv6 等价写法归一）。
- 存各来源有效结果；聚合/判断始终用当前版本重新计算（升级规则不会复用旧"干净/住宅"结论）。
- 时间字段区分：fetched_at(取得时间) / data_time(上游数据时间，未知为 null) / expires_at / served_at / cache_status。
- 读缓存不改写 fetched_at。
- 过期：先尝试刷新；刷新失败可展示旧数据但标 expired_refresh_failed；首次失败不生成"有效未命中"缓存。
- 代理凭据/API Key 不进入缓存（只存响应 data）。
- 支持 refresh=True 强制绕过。
"""
import ipaddress
import json
import os
import threading
import time

from ipcheck_lib.constants import VERSION

_LOCK = threading.Lock()
_CACHE = None
PARSER_VERSION = VERSION

# 各来源缓存 TTL（秒）
_TTL_GEO = 6 * 3600
_TTL_REGISTRY = 24 * 3600
_TTL_BGP = 300
_TTL_TOR = 3600
_TTL_REPUT = 30 * 60


def cache_path():
    return os.environ.get("IPCHECK_CACHE", "").strip() or os.path.join(
        os.path.expanduser("~"), ".ipcheck_cache.json")


def _ts(t=None):
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(t if t is not None else time.time()))


def default_ttl(source):
    if source in ("ipinfo", "ipapi", "ipwhois", "dbip", "maxmind"):
        return _TTL_GEO
    if source in ("rdap",):
        return _TTL_REGISTRY
    if source in ("ripe_bgp",):
        return _TTL_BGP
    if source in ("tor_exit",):
        return _TTL_TOR
    return _TTL_REPUT


def normalize_ip(ip):
    try:
        return ipaddress.ip_address(ip).compressed
    except ValueError:
        return ip


def make_key(source, ip, version=PARSER_VERSION):
    return "%s|%s|%s" % (version, source, normalize_ip(ip))


def _load():
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    try:
        with open(cache_path(), encoding="utf-8") as f:
            obj = json.load(f)
            _CACHE = obj if isinstance(obj, dict) else {}
    except Exception:
        _CACHE = {}  # 文件缺失/损坏：安全忽略
    return _CACHE


def _save():
    if _CACHE is None:
        return
    try:
        p = cache_path()
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_CACHE, f, ensure_ascii=False)
        os.replace(tmp, p)
    except Exception:
        pass


def reset():
    """测试用：清空内存缓存。"""
    global _CACHE
    with _LOCK:
        _CACHE = {}


def get_entry(source, ip):
    with _LOCK:
        return dict(_load().get(make_key(source, ip)) or {})


def put_entry(source, ip, data, data_time, ttl):
    with _LOCK:
        c = _load()
        now = time.time()
        c[make_key(source, ip)] = {"data": data, "fetched_at": _ts(now),
                                   "data_time": data_time, "expires_ts": now + ttl,
                                   "expires_at": _ts(now + ttl)}
        _save()


def _result(source, ok, data, error, status, query_time, data_time, expires_at, cache_status):
    return {"source": source, "ok": ok, "data": data, "error": error, "status": status,
            "query_time": query_time, "data_time": data_time, "expires_at": expires_at,
            "served_at": _ts(), "cache_status": cache_status}


def fetch(source, ip, fn, timeout, refresh=False, validator=None):
    """带缓存的单源查询；永不抛异常，返回统一结果 dict。"""
    key_src = source
    now = time.time()
    with _LOCK:
        ent = dict(_load().get(make_key(key_src, ip)) or {})
    if ent and not refresh and now < ent.get("expires_ts", 0):
        data = ent.get("data") or {}
        ok = bool(data) and (validator(data) if validator else True)
        return _result(source, ok, data, None, "ok" if ok else "empty",
                       ent.get("fetched_at"), ent.get("data_time"), ent.get("expires_at"), "valid")
    try:
        d = fn(ip, timeout)
        if not d or (validator and not validator(d)):
            raise RuntimeError("空响应/无有效字段")
        ttl = default_ttl(source)
        put_entry(source, ip, d, None, ttl)
        now2 = time.time()
        return _result(source, True, d, None, "ok", _ts(now2), None,
                       _ts(now2 + ttl), "refreshed" if ent else "fresh")
    except Exception as e:  # noqa: BLE001
        if ent:
            data = ent.get("data") or {}
            ok = bool(data) and (validator(data) if validator else True)
            return _result(source, ok, data,
                           "刷新失败，展示过期缓存：%s" % e,
                           "ok" if ok else "error", ent.get("fetched_at"),
                           ent.get("data_time"), ent.get("expires_at"),
                           "expired_refresh_failed")
        return _result(source, False, {}, str(e), "error", _ts(now), None, None, "none")


__all__ = ["fetch", "get_entry", "put_entry", "make_key", "normalize_ip",
           "default_ttl", "reset", "cache_path", "PARSER_VERSION"]
