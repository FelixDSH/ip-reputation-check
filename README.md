# ip-reputation-check

> 一条命令，多源并发把一个 IP 的「地理 / ASN / 代理 / VPN / 机房 / 欺诈分 / 滥用记录 / 综合风险」一次查清。
> 纯 Python 标准库实现，可作为 **skill** 被任意 agent 加载：对话里输入一个 IP，直接返回检测结果。

![demo](examples/demo.txt)

## 为什么做这个

做跨境网络 / 代理 / 机场选型时，判断一个 IP 干不干净，通常要挨个打开
ipinfo.io、iphub.info、scamalytics.com、abuseipdb.com 手动输入——非常繁琐。
本项目把这些源聚合成一次调用，并额外提供**出口 IP 稳定性测试**（断开重连前后比对）。

## 数据源

| 源 | 提供 | 是否需要 Key |
|----|------|--------------|
| ipinfo.io | 地理 / ASN / Org / 主机名 | 否（可配 `IPINFO_TOKEN` 提额） |
| ip-api.com | 地理 + proxy / hosting / mobile 标记 | 否 |
| ipwho.is | 地理 / ASN（备用源） | 否 |
| proxycheck.io | proxy / VPN / 网络类型 / risk | 否（免 key 有日限） |
| scamalytics.com | Fraud Score + 风险等级 | 否（网页解析；可配 API） |
| iphub.info | block 等级 + proxyType（proxy/tor/hosting/residentialProxy） | 游客免 key（高信誉出口直出，机房可能触发 Turnstile）；推荐 `IPHUB_API_KEY` |
| abuseipdb.com | Abuse Confidence / 报告数 | 是：`ABUSEIPDB_API_KEY` |

缺 key 的源会自动跳过并在报告里标注，不影响其它指标。

## 快速开始

```bash
git clone https://github.com/FelixDSH/ip-reputation-check.git
cd ip-reputation-check

# 单 IP
python scripts/ipcheck.py check 8.8.8.8

# 多 IP + JSON
python scripts/ipcheck.py check 8.8.8.8 1.1.1.1 --json

# 我的出口 IP
python scripts/ipcheck.py myip

# 稳定性：连续采样 / 断开重连对比
python scripts/ipcheck.py stability --rounds 5 --interval 3
python scripts/ipcheck.py stability --interactive
```

示例输出：

```
============================================================
IP 信誉检测报告  212.68.185.88
============================================================
位置        : Japan Kanagawa Kawasaki   时区 Asia/Tokyo
ASN / 组织  : AS58325 Hydra Communications Ltd
ISP         : Hydra Communications Ltd
网络类型    : VPN
------------------------------------------------------------
代理 Proxy  : 是    VPN: 是    托管 Hosting: 否
移动网络    : 否    Tor: 未知
------------------------------------------------------------
欺诈分(Scamalytics): 0/100  (Low Risk)
滥用置信度(AbuseIPDB): —（需 ABUSEIPDB_API_KEY）
------------------------------------------------------------
综合判定    : 65/100  🟠 中高风险
------------------------------------------------------------
数据源 成功 : ipinfo.io, ip-api.com, ipwho.is, proxycheck.io, scamalytics.com
数据源 跳过 : iphub.info(未配置 IPHUB_API_KEY，跳过), abuseipdb.com(未配置 ABUSEIPDB_API_KEY，跳过)
============================================================
```

## 配置 Key（可选）

```bash
export IPHUB_API_KEY=你的key
export ABUSEIPDB_API_KEY=你的key
# 可选
export IPINFO_TOKEN=你的token
export SCAMALYTICS_USER=你的user
export SCAMALYTICS_KEY=你的key
```

Windows PowerShell：

```powershell
$env:IPHUB_API_KEY="你的key"
$env:ABUSEIPDB_API_KEY="你的key"
```

## 命令行参数

```
ipcheck check <IP...> [--json] [--only a,b,...] [--gateway URL] [--timeout 12] [--no-color]
ipcheck myip [--json]
ipcheck stability [--rounds N] [--interval S] [--interactive] [--json] [--only ...]
```

`--only` 可选值：`ipinfo,ipapi,ipwhois,proxycheck,scamalytics,iphub,abuseipdb`

客户端相关环境变量：`IPCHECK_GATEWAY`（网关地址）、`IPCHECK_GATEWAY_TOKEN`（网关令牌）。
服务端（网关）相关：`IPHUB_API_KEY`、`ABUSEIPDB_API_KEY`、`IPINFO_TOKEN`、`GATEWAY_TOKEN`。

## 人机验证（Captcha）怎么解决

不同站点的反爬强度不一样，先分清三类：

| 类型 | 站点 | 表现 | 对策 |
|------|------|------|------|
| 干净 JSON API | ipinfo / ip-api / ipwho.is / proxycheck | 无验证码 | 直接用（本工具默认就走这些） |
| 站点要 token | **iphub 游客接口** | 机房/VPN 出口返回 `captchaRequired:true`（Cloudflare Turnstile）；住宅出口通常直接出结果 | ① 免费 API key（首选）② 真实浏览器人工过验证 ③ 第三方打码 |
| Cloudflare 403 | **abuseipdb 网页版** | 直接 403 | 用官方 API key（免费 1000/天） |

**核心结论：能用官方/免费 JSON API 就别硬刚验证码**——最稳、最省事。本工具已把所有能免验证码的源做成默认通道，验证码只在 iphub 游客接口 / abuseipdb 网页版出现，且都能被 API key 彻底绕开。

真必须过验证码时，按可靠度从高到低：

**1) 官方 API Key（首选）**
- iphub：iphub.info 免费注册 → `IPHUB_API_KEY`
- abuseipdb：abuseipdb.com 免费 1000 次/天 → `ABUSEIPDB_API_KEY`

**2) 真实浏览器自动化（人工过一次）**
- 用 Playwright 起真实 Chrome（非 headless），人工完成 Turnstile，脚本抓 `/api/lookup/ip` 的 JSON。
- 本仓库自带：`python scripts/iphub_browser.py <IP>`

**3) 第三方打码（Turnstile 求解）**
- 服务：CapSolver / 2Captcha / YesCaptcha，均支持 `AntiTurnstileTaskProxyLess`。
- 流程：取 sitekey + pageurl → 建任务 → 轮询拿 token → 作为 `cf-turnstile-response` 提交。
- sitekey 从页面里的 `challenges.cloudflare.com/turnstile/...?sitekey=XXXX` iframe src 提取。

```python
# CapSolver 解 Turnstile 骨架（占位符自行替换）
import os, time, requests
SITEKEY, PAGEURL, APIKEY = "TURNSTILE_SITEKEY", "https://iphub.info/", "CAPSOLVER_KEY"
tid = requests.post("https://api.capsolver.com/createTask", json={
    "clientKey": APIKEY,
    "task": {"type": "AntiTurnstileTaskProxyLess",
             "websiteURL": PAGEURL, "websiteKey": SITEKEY}}).json()["taskId"]
while True:
    r = requests.post("https://api.capsolver.com/getTaskResult",
                      json={"clientKey": APIKEY, "taskId": tid}).json()
    if r.get("status") == "ready":
        os.environ["IPHUB_TURNSTILE_TOKEN"] = r["solution"]["token"]; break
    time.sleep(2)
# 之后：python scripts/ipcheck.py check <IP> --only iphub  # 会自动带上 token
```

**4) 降低触发概率**
- 用住宅/移动代理出口（机房 IP 几乎必触发）
- 规范 UA / Accept-Language、控制频率（`--interval`）、复用 cookie 会话
- 别用裸脚本高频打同一接口

> 说明：验证码是对方的风控。优先官方 API；自用/有权限场景下再考虑浏览器或打码，并控制频率。

## 命令行参数

## 为什么不要把 key 写进分发的 skill（多人共用正确姿势）

**API Key 绑定的是「你账号」的配额。** 把 key 硬编码进一个给很多人用的 skill：
- 所有人共用你一份额度 → 很快被限流/封禁；
- 开源代码里泄露 key → 任何人都能盗用。

正确做法是「免 key 优先 + BYOK + 共享网关」：

| 场景 | 做法 |
|------|------|
| 开源分发给任意人 | **免 key 即可用**（ipinfo/ip-api/ipwho.is/proxycheck/scamalytics 5 个源零 key），需要 iphub/abuseipdb 精度的人**各自申请自己的免费 key**（BYOK） |
| 团队/多人共用一个出口检测 | 部署**一台网关**：key 只放服务端，客户端零 key，网关做缓存+限流保护额度 |

### 网关模式（团队共用一份 key 也不炸）

```bash
# 服务端（只这一台配 key）
export IPHUB_API_KEY=xxx
export ABUSEIPDB_API_KEY=xxx
python scripts/gateway.py --host 0.0.0.0 --port 8787 --ttl 300 --rate 60 --token SECRET

# 任意客户端（无需任何源 key）
export IPCHECK_GATEWAY=http://网关IP:8787
export IPCHECK_GATEWAY_TOKEN=SECRET
python scripts/ipcheck.py check 8.8.8.8
```

网关内置：**TTL 缓存**（同 IP 在 TTL 内只查一次，省额度）、**每 IP 每分钟限流**、可选**访问令牌**。
接口：`GET /check?ip=8.8.8.8` → 聚合 JSON；`GET /health` → 健康检查。

## 风险判定模型

- 外部分：取 Scamalytics 欺诈分与 AbuseIPDB 置信度的较大值（0–100）。
- 信号分：Proxy +30、VPN +35、Hosting +10、Tor +60、Mobile −5。
- 综合风险分 = min(100, max(外部分, 信号分))；等级 `<20` 干净、`20–49` 中低、`50–79` 中高、`≥80` 高。
- 源间冲突（例如 ip-api 说 proxy、proxycheck 说 no）会在报告「备注」中说明，并按可信源优先级取值。

## 作为 agent skill 使用

把整个仓库（或仅 `SKILL.md` + `scripts/`）放到对应 skill 目录即可被加载：

| 平台 | 目录 |
|------|------|
| Claude Code | `~/.claude/skills/ip-reputation-check/` |
| Codex | `~/.codex/skills/ip-reputation-check/` |
| 通用 Agents（豆包 / Trae 等） | `~/.agents/skills/ip-reputation-check/` |

加载后对 agent 说「帮我查一下 1.2.3.4 这个 IP」，它会自动执行脚本并汇总结果。

## 免责声明 / Notes

- 判定「代理 / VPN / 机房」不代表该 IP 恶意；Cloudflare、Google 等 CDN/公共 DNS 常被标为 hosting。
- 免费源有速率限制，批量场景请自备 Key 或放慢节奏（`--interval`）。
- 各情报源数据仅供网络质量与风险参考，最终以实际网络行为为准。

## License

MIT © 2026 FelixDSH
