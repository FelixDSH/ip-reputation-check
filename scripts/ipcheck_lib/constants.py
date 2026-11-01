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

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0 Safari/537.36")

VERSION = "1.0.0"

DEFAULT_TIMEOUT = 12

RISK_W_PROXY = 30

RISK_W_VPN = 35

RISK_W_HOSTING = 10

RISK_W_TOR = 60

RISK_W_MOBILE = -5

RISK_T_CLEAN = 20

RISK_T_LOW = 50

RISK_T_MEDIUM = 80

CLOUD_HINTS = ("amazon", "aws", "google", "microsoft", "azure", "digitalocean",
               "linode", "akamai", "cloudflare", "ovh", "hetzner", "vultr",
               "alibaba", "aliyun", "tencent", "oracle", "gcore", "leaseweb",
               "choopa", "contabo", "hosting", "datacenter", "data center",
               "server", "colo")

PLATFORM_PROFILES = {
    "社交媒体(X/FB/IG/TikTok)": {"hosting": 45, "proxy": 45, "vpn": 45, "tor": 85,
                               "mobile": -20, "abuse": 30},
    "AI工具(OpenAI/Claude/Gemini)": {"hosting": 55, "proxy": 55, "vpn": 55, "tor": 85,
                                    "mobile": -10, "abuse": 30, "country_restricted": 95},
    "电商/支付(Amazon/PayPal)": {"hosting": 60, "proxy": 60, "vpn": 60, "tor": 90,
                              "mobile": -10, "abuse": 40},
    "流媒体(Netflix/Spotify)": {"hosting": 40, "proxy": 35, "vpn": 40, "tor": 80,
                             "mobile": -15, "abuse": 20},
    "注册/论坛/爬虫": {"hosting": 45, "proxy": 50, "vpn": 50, "tor": 85,
                   "mobile": -15, "abuse": 35},
}

AI_RESTRICTED = {"CN", "RU", "IR", "KP", "SY", "CU", "BY", "VE", "MM"}

PLATFORMS = {
    "X (Twitter)": {"cat": "社交媒体(X/FB/IG/TikTok)", "strict": 1.05, "note": "机房/VPN 易触发手机号验证或封号"},
    "Facebook/Instagram": {"cat": "社交媒体(X/FB/IG/TikTok)", "strict": 1.15, "note": "新号+机房IP 极易封，需养号"},
    "TikTok": {"cat": "社交媒体(X/FB/IG/TikTok)", "strict": 1.2, "note": "强地区限制，需目标区住宅/移动IP"},
    "Telegram": {"cat": "社交媒体(X/FB/IG/TikTok)", "strict": 0.55, "note": "对 VPN/代理较宽松"},
    "WhatsApp": {"cat": "社交媒体(X/FB/IG/TikTok)", "strict": 0.8, "note": "需手机号，IP 敏感度中等"},
    "Google/Gmail": {"cat": "注册/论坛/爬虫", "strict": 1.1, "note": "机房IP注册常要手机验证"},
    "OpenAI/ChatGPT": {"cat": "AI工具(OpenAI/Claude/Gemini)", "strict": 1.1, "note": "杀机房 + 地区限制"},
    "Claude": {"cat": "AI工具(OpenAI/Claude/Gemini)", "strict": 1.1, "note": "杀机房 + 地区限制"},
    "Gemini": {"cat": "AI工具(OpenAI/Claude/Gemini)", "strict": 0.9, "note": "机房较敏感"},
    "Midjourney": {"cat": "AI工具(OpenAI/Claude/Gemini)", "strict": 0.8, "note": "走 Discord，IP 敏感度中"},
    "Amazon": {"cat": "电商/支付(Amazon/PayPal)", "strict": 1.15, "note": "新号+代理IP 高风险"},
    "PayPal": {"cat": "电商/支付(Amazon/PayPal)", "strict": 1.25, "note": "风控最严，机房/代理基本不可用"},
    "Binance/交易所": {"cat": "电商/支付(Amazon/PayPal)", "strict": 1.3, "note": "KYC + 地区 + 设备风控极严"},
    "Netflix": {"cat": "流媒体(Netflix/Spotify)", "strict": 1.0, "note": "封 VPN，需原生住宅"},
    "Spotify": {"cat": "流媒体(Netflix/Spotify)", "strict": 0.65, "note": "地区限制为主"},
}

SERVICE_REGIONS = {
    "OpenAI/ChatGPT": {"restricted": set(AI_RESTRICTED) | {"SD", "SS", "AF"}, "note": "需支持地区 + 非机房"},
    "Claude": {"restricted": set(AI_RESTRICTED) | {"SD", "SS"}, "note": "需支持地区"},
    "Gemini": {"restricted": {"CN", "RU", "KP", "IR", "SY", "CU"}, "note": ""},
    "Netflix": {"restricted": {"CN", "KP", "SY", "IR", "RU"}, "note": "地区内容不同，封VPN"},
    "Spotify": {"restricted": {"CN", "KP", "IR", "SY"}, "note": ""},
    "TikTok": {"restricted": {"CN", "IR", "KP", "IN", "SY"}, "note": "部分地区禁用"},
    "PayPal": {"restricted": {"IR", "KP", "SY", "CU", "SD", "SS"}, "note": ""},
    "Binance": {"restricted": {"US", "CN", "IR", "KP", "SY", "CU"}, "note": "美国需 binance.us"},
    "Steam": {"restricted": {"KP", "IR", "SY", "CU"}, "note": ""},
}

SOURCE_LABEL = {
    "ipinfo": "ipinfo.io", "ipapi": "ip-api.com", "ipwhois": "ipwho.is",
    "proxycheck": "proxycheck.io", "scamalytics": "scamalytics.com",
    "iphub": "iphub.info", "abuseipdb": "abuseipdb.com",
    "stopforumspam": "stopforumspam.com", "blocklistde": "blocklist.de",
    "ipsum": "IPsum(聚合黑名单)", "spamhaus": "Spamhaus DNSBL",
    "virustotal": "VirusTotal", "dbip": "DB-IP", "maxmind": "MaxMind GeoLite2",
}

SOURCE_TIER = {
    "ipinfo": "A", "spamhaus": "A", "virustotal": "A", "maxmind": "A", "dbip": "A",
    "ipapi": "B", "proxycheck": "B", "blocklistde": "B",
    "ipwhois": "C", "iphub": "C", "scamalytics": "C",
    "abuseipdb": "C", "stopforumspam": "C", "ipsum": "C",
}

TIER_WEIGHT = {"A": 3, "B": 2, "C": 1}

DECISION_LABEL = {"ok": "✅ 较适合", "warn": "⚠️ 谨慎", "no": "⛔ 风险高"}


__all__ = ['UA', 'VERSION', 'DEFAULT_TIMEOUT', 'RISK_W_PROXY', 'RISK_W_VPN', 'RISK_W_HOSTING', 'RISK_W_TOR', 'RISK_W_MOBILE', 'RISK_T_CLEAN', 'RISK_T_LOW', 'RISK_T_MEDIUM', 'CLOUD_HINTS', 'PLATFORM_PROFILES', 'AI_RESTRICTED', 'PLATFORMS', 'SERVICE_REGIONS', 'SOURCE_LABEL', 'SOURCE_TIER', 'TIER_WEIGHT', 'DECISION_LABEL']
