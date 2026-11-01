# -*- coding: utf-8 -*-
"""cache.py — 来源级结果缓存（只缓存各来源原始结果，不缓存最终判断）。

要点：
- 键 = 解析器版本 + 来源 + 规范化 IP；存各来源有效结果；聚合始终用当前版本重算。
- 时间字段：fetched_at / data_time / expires_at / served_at / cache_status。
- 读缓存不改写 fetched_at；名单源以"名单实际取得时间"作为 fetched_at。
- 过期分级：在允许回退期内 -> 可用但标 expired_refresh_failed；超过 max_stale -> 仅历史、不参与判断(ok=False)。
- 条目校验：非 dict / data 非 dict / 时间字段类型错 -> 忽略重查。
- 支持 refresh=True 强制绕过（也穿透来源内部名单缓存，通过传 refresh 给支持它的函数）。
"""
import inspect
import ipaddress
import json
import os
import threading
import time

from ipcheck_lib.constants import VERSION

_LOCK = threading.Lock()
_CACHE = None
PARSER_VERSION = VERSION

_TTL_GEO = 6 * 3600
_TTL_REGISTRY = 24 * 3600
_TTL_BGP = 300
_TTL_TOR = 3600
_TTL_REPUT = 30 * 60

_DAY = 86400
_MAX_STALE = {
    "ipinfo": 30 * _DAY, "ipapi": 30 * _DAY, "ipwhois": 30 * _DAY, "dbip": 30 * _DAY,
    "maxmind": 30 * _DAY, "rdap": 90 * _DAY, "ripe_bgp": 1 * _DAY, "tor_exit": 7 * _DAY,
}
_MAX_STALE_DEFAULT = 7 * _DAY


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


def max_stale(source):
    return _MAX_STALE.get(source, _MAX_STALE_DEFAULT)


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
        _CACHE = {}
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
    global _CACHE
    with _LOCK:
        _CACHE = {}


def _valid_entry(ent):
    """条目结构校验：类型不对就丢弃（不崩溃）。"""
    if not isinstance(ent, dict):
        return False
    if not isinstance(ent.get("data"), dict):
        return False
    if not isinstance(ent.get("expires_ts"), (int, float)):
        return False
    if not isinstance(ent.get("fetched_at"), str):
        return False
    return True


def get_entry(source, ip):
    with _LOCK:
        ent = _load().get(make_key(source, ip))
        return dict(ent) if _valid_entry(ent) else {}


def put_entry(source, ip, data, data_time, ttl, fetched_at=None):
    with _LOCK:
        c = _load()
        now = time.time()
        c[make_key(source, ip)] = {
            "data": data, "fetched_at": fetched_at or _ts(now),
            "data_time": data_time, "expires_ts": now + ttl, "expires_at": _ts(now + ttl)}
        _save()


def _call_source(fn, ip, timeout, refresh):
    try:
        params = inspect.signature(fn).parameters
        accepts = "refresh" in params or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
    except (TypeError, ValueError):
        accepts = False
    return fn(ip, timeout, refresh=refresh) if accepts else fn(ip, timeout)


def _result(source, ok, data, error, status, query_time, data_time, expires_at, cache_status, **extra):
    r = {"source": source, "ok": ok, "data": data, "error": error, "status": status,
         "query_time": query_time, "data_time": data_time, "expires_at": expires_at,
         "served_at": _ts(), "cache_status": cache_status}
    r.update(extra)
    return r


def fetch(source, ip, fn, timeout, refresh=False, validator=None):
    """带缓存的单源查询；永不抛异常，返回统一结果 dict。"""
    now = time.time()
    with _LOCK:
        raw = _load().get(make_key(source, ip))
        ent = dict(raw) if _valid_entry(raw) else {}

    if ent and not refresh and now < ent["expires_ts"]:
        data = ent["data"]
        ok = bool(data) and (validator(data) if validator else True)
        return _result(source, ok, data, None, "ok" if ok else "empty",
                       ent["fetched_at"], ent.get("data_time"), ent.get("expires_at"), "valid")

    try:
        d = _call_source(fn, ip, timeout, refresh)
        if not d or (validator and not validator(d)):
            raise RuntimeError("空响应/无有效字段")
        data_time = d.get("list_fetched_at") if isinstance(d, dict) else None
        fetched_at = data_time or _ts(now)
        ttl = default_ttl(source)
        put_entry(source, ip, d, data_time, ttl, fetched_at=fetched_at)
        return _result(source, True, d, None, "ok", fetched_at, data_time,
                       _ts(now + ttl), "refreshed" if ent else "fresh")
    except Exception as e:  # noqa: BLE001
        if ent:
            data = ent["data"]
            ok = bool(data) and (validator(data) if validator else True)
            stale = now - ent["expires_ts"]
            if stale > max_stale(source):
                return _result(source, False, data,
                               "过期过久(仅历史，不参与判断)：%s" % e, "stale",
                               ent["fetched_at"], ent.get("data_time"), ent.get("expires_at"),
                               "expired_too_old", stale_seconds=int(stale))
            return _result(source, ok, data, "刷新失败，展示过期缓存：%s" % e,
                           "ok" if ok else "error", ent["fetched_at"], ent.get("data_time"),
                           ent.get("expires_at"), "expired_refresh_failed", stale_seconds=int(stale))
        return _result(source, False, {}, str(e), "error", _ts(now), None, None, "none")


__all__ = ["fetch", "get_entry", "put_entry", "make_key", "normalize_ip", "default_ttl",
           "max_stale", "reset", "cache_path", "PARSER_VERSION"]
