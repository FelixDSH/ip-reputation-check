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

def _make_opener():
    # 使用标准安全上下文（不降低 TLS 级别）。个别站点握手失败时再按需回退，避免全局降级。
    ctx = ssl.create_default_context()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler(),          # 尊重系统代理 / 环境变量
        urllib.request.HTTPSHandler(context=ctx),
    )

_OPENER = _make_opener()

def http_get(url, headers=None, timeout=DEFAULT_TIMEOUT, retries=1):
    """返回 (status, text)。失败抛异常。"""
    h = {"User-Agent": UA, "Accept": "application/json, text/html, */*"}
    if headers:
        h.update(headers)
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=h)
            with _OPENER.open(req, timeout=timeout) as resp:
                raw = resp.read()
                enc = resp.headers.get_content_charset() or "utf-8"
                return resp.status, raw.decode(enc, "replace")
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt < retries:
                time.sleep(0.6 * (attempt + 1))
    raise last

def _j(text):
    return json.loads(text)

def http_post_json(url, body_obj, headers=None, timeout=DEFAULT_TIMEOUT, retries=1):
    """POST JSON，返回 (status, text)。"""
    h = {"User-Agent": UA, "Accept": "application/json",
         "Content-Type": "application/json"}
    if headers:
        h.update(headers)
    payload = json.dumps(body_obj).encode("utf-8")
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=payload, headers=h, method="POST")
            with _OPENER.open(req, timeout=timeout) as resp:
                raw = resp.read()
                enc = resp.headers.get_content_charset() or "utf-8"
                return resp.status, raw.decode(enc, "replace")
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read().decode("utf-8", "replace")
            except Exception:
                last = e
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt < retries:
                time.sleep(0.6 * (attempt + 1))
    raise last

def _to_int(v):
    try:
        return int(float(v))
    except Exception:
        return None

def _pick(*vals):
    for v in vals:
        if v is not None and v != "" and v is not False:
            return v
    return None


__all__ = ['_make_opener', '_OPENER', 'http_get', '_j', 'http_post_json', '_to_int', '_pick']
