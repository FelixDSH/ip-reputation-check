# ip-reputation-check

> 一条命令，多源并发把一个 IP 的「地理 / ASN / 代理 / VPN / 机房 / 欺诈分 / 滥用记录 / 综合风险」一次查清，
> 并给出**每个维度的置信度（高/中/低）**。纯 Python 标准库，可作为 **skill** 被任意 agent 加载。
>
> ⚠️ **定位：多源聚合初筛 + 置信度提示，不是权威风控判定。** 免费源精度有限，重要决策请交叉验证或改用商业 API（见下文权威替代）。

示例输出见 [examples/demo.txt](examples/demo.txt)。

## 极简用法

**在对话里直接把 IP 发出来就行**（agent 加载本 skill 后会自动执行），或本地一条命令：

```bash
python scripts/ipcheck.py 8.8.8.8            # 直接给 IP，无需子命令
python scripts/ipcheck.py 8.8.8.8 --brief    # 一行式简报
```

默认**零配置**即可运行（约 10 个免 key 源：地理/代理/欺诈/滥用多源聚合）。只有需要下面两项额外指标时，才各自配**自己的**免费 key：

| 你想要 | 额外条件 |
|--------|----------|
| 基础判定：位置 / ASN / 代理 / VPN / 机房 / 欺诈分 / 综合风险 | 无，直接跑 |
| 其他滥用举报信号（StopForumSpam / blocklist.de / IPsum） | 无，自动显示 |
| iphub：代理类型细分（住宅/机房/住宅代理） | 免费 `IPHUB_API_KEY`；或本机跑 `scripts/iphub_browser.py` 人工过验证 |
| abuseipdb：滥用置信度 | 免费 `ABUSEIPDB_API_KEY`；或 `ipcheck.py open <IP>` 打开网页人工看（网页免 key） |

## 项目结构（已拆包）

```
scripts/
├── ipcheck.py            # 入口 shim（向后兼容，所有 ipcheck.<name> 仍可用）
└── ipcheck_lib/
    ├── constants.py      # 版本/权重/平台·服务规则库等常量
    ├── http.py           # HTTP/JSON、DNS 查询、通用取值助手
    ├── sources.py        # 14 个情报源适配器 + 注册表
    ├── scoring.py        # 聚合、风险评分、置信度、类型/平台决策
    ├── render.py         # 报表 / 简报 / JSON 渲染
    ├── env.py            # 出口 IP、时区/DNS 环境一致性
    ├── csvio.py          # 批量 CSV 导出、地区可用性
    └── cli.py            # 子命令与参数解析
gateway.py / setup_geoip.py / iphub_browser.py   # 独立工具
tests/  (test_core.py, test_consistency.py)
```
入口仍是 `scripts/ipcheck.py`；`build.ps1` 用 PyInstaller onefile 打单文件 exe，兼顾"拆包维护"与"单文件分发"。

## 自检 / 测试

```bash
python tests/test_core.py          # 核心逻辑单测：各源 parser、_vote 冲突、geo 选取、评分阈值、置信度平票、CSV 注入、iphub 分支
python tests/test_consistency.py   # 10 种 IP 类型 × 文案自洽性
```
CI（`.github/workflows/ci.yml`）在 push/PR 时跑 **Python 3.8 / 3.10 / 3.12 + Windows** 矩阵，并做 `--version`/`--help` 冒烟。

## 环境要求（用户要装什么？）

**基础检测的唯一硬性依赖是 Python 3.8+，而且不用 `pip` 装任何第三方库**（全部标准库）。不需要 Node、不需要浏览器。

| 使用方式 | 用户需要什么 |
|----------|--------------|
| 作为 agent skill 调起（Claude Code / Codex / 通用 agents） | 只要运行 agent 的机器有 **Python 3.8+** |
| 自己命令行运行 | **Python 3.8+**（无需 pip 装包） |
| 给非技术用户 / 不想装 Python（Windows） | 用打包好的 **`dist/ipcheck.exe`** 单文件，双击或 `ipcheck.exe 8.8.8.8`，**完全不需要 Python** |
| 完全零安装、多人共用 | 部署一台 `gateway.py` + 网页，用户只用浏览器 |

> 只有当你额外使用 `--browser` / `iphub_browser.py`（用真实浏览器过 iphub 验证码）时，才需要 Playwright + 本机 Chrome；基础检测不需要。

### 自己打 Windows 免安装 exe

```powershell
./build.ps1           # 产出 dist/ipcheck.exe（单文件，约 9MB）
# 或手动：
python -m pip install pyinstaller
python -m PyInstaller --onefile --name ipcheck --distpath dist --workpath build --specpath build scripts/ipcheck.py
```

打出来后分发 `dist/ipcheck.exe` 即可，对方无需安装任何东西（Windows 直接运行）。

### 地理升级到 MaxMind GeoLite2（免费、最权威）

不配置时已用 **DB-IP（免 key）** 交叉校验地理。想要"最权威"再接 MaxMind GeoLite2：

1. 免费注册 MaxMind → 生成 License Key： https://www.maxmind.com/en/geolite2/signup
2. `pip install maxminddb`
3. `python scripts/setup_geoip.py --license-key YOUR_KEY`（自动下载到 `data/`）
4. 之后 ipcheck 自动生效（或 `set GEOIP2_MMDB=<路径>`）

> 国内下载慢可挂代理，或手动把 `GeoLite2-City.mmdb` 放进 `data/` 目录即可。

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
| stopforumspam.com | 垃圾信息 / 滥用举报频率 | 否 |
| blocklist.de | 攻击举报数 | 否 |
| IPsum（GitHub） | 聚合黑名单命中条数 | 否 |
| **Spamhaus DNSBL** | SBL/XBL/PBL 权威反滥用名单 | 否（DNS 低量） |
| **VirusTotal** | 70+ 引擎聚合恶意判定 | 可选 `VIRUSTOTAL_API_KEY` |
| **DB-IP** | 地理（正规数据商，免 key 交叉源） | 否 |
| **MaxMind GeoLite2** | 地理（最权威，本地库） | 免费 License Key + `maxminddb` |

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
IP 类型     : VPN
------------------------------------------------------------
代理 Proxy  : 是    VPN: 是    托管 Hosting: 否
移动网络    : 否    Tor: 未知
------------------------------------------------------------
欺诈分(Scamalytics): 0/100  (Low Risk)
滥用置信度(AbuseIPDB): —（需 ABUSEIPDB_API_KEY）
滥用举报(免key)      : StopForumSpam频率:0  blocklist.de攻击:0  IPsum:未命中
权威滥用源  : Spamhaus:未命中
------------------------------------------------------------
综合判定    : 65/100  🟠 中高风险
置信度      : 地理:高  代理:高  VPN:低  托管:高  滥用:低
------------------------------------------------------------
平台适配度(启发式,非平台真实判定):
  🔴 易被风控  社交媒体(X/FB/IG/TikTok)  代理, VPN
  🔴 易被风控  AI工具(OpenAI/Claude/Gemini)  代理, VPN
  🔴 易被风控  电商/支付(Amazon/PayPal)  代理, VPN
  🔴 易被风控  流媒体(Netflix/Spotify)  代理, VPN
  🔴 易被风控  注册/论坛/爬虫  代理, VPN
------------------------------------------------------------
使用建议(启发式,综合IP画像):
  ⛔ 不建议  注册社媒/AI 账号     代理/VPN/Tor IP 极易被判异常、要求验证或封号
  ⛔ 不建议  长期养号           机房/代理/VPN IP 不利于长期养号，易被清理
  ⚠️ 谨慎  爬虫/数据采集        可用，但非机房 IP 做采集成本高/易触发
  ⛔ 不建议  电商/支付          风控最严，机房/代理/滥用 IP 基本不可用
  ⚠️ 谨慎  流媒体解锁          VPN 可能被封（Netflix 等），需实测
------------------------------------------------------------
数据源 成功 : ipinfo.io, ip-api.com, ipwho.is, proxycheck.io, scamalytics.com, stopforumspam.com, blocklist.de, IPsum(聚合黑名单), Spamhaus DNSBL, DB-IP
数据源 跳过 : iphub.info(需人机验证), abuseipdb.com(需 key), VirusTotal(未配置 VIRUSTOTAL_API_KEY), MaxMind GeoLite2(未配置)
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
ipcheck check <IP...> [--file F] [--csv out.csv] [--json] [--brief] [--open] [--env] [--platforms] [--regions] [--interval S] [--only ...] [--gateway URL]
ipcheck open <IP> [--all] [--which abuseipdb,iphub,scamalytics,stopforumspam]
ipcheck myip [--json]        # 出口 IP + 环境一致性
ipcheck stability [--rounds N] [--interval S] [--interactive] [--json] [--only ...]
ipcheck watch [IP...] [--egress] [--interval 60] [--rounds N]   # 监控变化/漂移
```

`--only` 可选值：`ipinfo,ipapi,ipwhois,proxycheck,scamalytics,iphub,abuseipdb,stopforumspam,blocklistde,ipsum,spamhaus,virustotal,dbip,maxmind`

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

## 滥用举报记录：不止 AbuseIPDB（这些免 key）

AbuseIPDB 前端对程序化访问会拦（返回 "Please Don't Scrape"），程序里只能走免费 key。但**滥用/举报类信号并非只有它**，工具已内置几个完全免 key 的渠道：

| 渠道 | 指标 | key |
|------|------|-----|
| StopForumSpam | 垃圾信息 / 滥用举报频率 | 免 |
| blocklist.de | 攻击举报数 | 免 |
| IPsum | 聚合 30+ 个黑名单的命中条数 | 免 |
| Scamalytics | 欺诈分（也可作滥用参考） | 免 |

报表会显示：`滥用举报(免key): StopForumSpam频率:X  blocklist.de攻击:Y  IPsum:命中/未命中`，并计入综合风险。

### 一键打开网页并自动填入 IP（人工核验）

有些站人肉打开最省事，工具会自动把 IP 拼进网址打开浏览器：

```bash
python scripts/ipcheck.py open 8.8.8.8          # 默认打开 abuseipdb 检查页
python scripts/ipcheck.py open 8.8.8.8 --all    # abuseipdb / iphub / scamalytics / stopforumspam 全开
python scripts/ipcheck.py 8.8.8.8 --open        # 检测完顺带打开 abuseipdb + iphub（IP 已带入）
```

## 为什么不要把 key 写进分发的 skill（多人共用正确姿势）

**API Key 绑定的是「你账号」的配额。** 把 key 硬编码进一个给很多人用的 skill：
- 所有人共用你一份额度 → 很快被限流/封禁；
- 开源代码里泄露 key → 任何人都能盗用。

正确做法是「免 key 优先 + BYOK + 共享网关」：

| 场景 | 做法 |
|------|------|
| 开源分发给任意人 | **免 key 即可用**（ipinfo/ip-api/ipwho.is/proxycheck/scamalytics/StopForumSpam/blocklist.de/IPsum/Spamhaus/DB-IP 等约 10 个源零 key），需要 iphub/abuseipdb 精度的人**各自申请自己的免费 key**（BYOK） |
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

## 源权威度 & 置信度（重要）

**没有任何单一网站是「权威真相」。** 本项目把源分成三档，并按「源等级 × 多源一致度」给每个维度打置信度：

| 档 | 含义 | 本工具中的源 |
|----|------|--------------|
| **A 权威/商业** | 正规数据源，可信度高 | ipinfo、Spamhaus、VirusTotal |
| **B 专业** | 专用检测，较可信 | ip-api、proxycheck、blocklist.de |
| **C 社区/聚合** | 参考信号，噪声较大 | ipwho.is、iphub、scamalytics、AbuseIPDB、StopForumSpam、IPsum |

报表会输出：`置信度: 地理:高 代理:中 VPN:低 托管:高 滥用:低`
- **高** = 多个（含高等级）源结果一致；**中** = 基本一致但有分歧；**低** = 单一源或源间冲突。
- **滥用为「低」只代表没有权威源命中，不等于干净**（AbuseIPDB 官方也强调 0 报告 ≠ 安全）。

### 能做什么 / 不能做什么
- ✅ 快速初筛：这 IP 大概在哪、是不是代理/机房、有没有被拉黑。
- ✅ 平台适配度初筛：这 IP 适不适合注册/使用社媒、AI 工具、电商支付、流媒体。
- ✅ 多源对比 + 冲突提示：让你知道**这个结论有多可信**，而不是假装权威。
- ❌ 不能当风控/封禁的唯一依据；地理城市级只有 ~50–80% 准确；住宅代理必然有漏报。

### 想要更高可信度 → 换商业 API
`MaxMind GeoIP2 / minFraud`、`IPQualityScore`、`Spur`、`VirusTotal`、`Spamhaus`、`Cisco Talos` 才适合严谨风控。

## IP 类型细分 & 环境一致性（防关联）

**IP 类型细分**：除了「是不是机房」，还会归类为 住宅/移动(4G/5G)/机房云主机/企业/教育/政府/Tor/VPN/代理。
报表里直接看 `IP 类型`，也用于平台适配度判断（住宅/移动更"像真人"）。

**环境一致性检测**（防关联指纹，别人很少做）：
```bash
python scripts/ipcheck.py myip            # 看自己出口 IP + 环境一致性
python scripts/ipcheck.py <IP> --env      # 检查某 IP 时附带环境比对
```
检测两项「穿帮」信号：
- **时区**：本机时区 vs 出口 IP 大致时区是否一致（差 ≥2 小时 → 浏览器时区指纹穿帮）
- **DNS 出口**：DNS 解析器所在国 vs IP 所在国（不一致 → 可能 DNS 泄漏/未全程走代理）

示例（本机在国内、却用日本代理但没走 DNS）：
```
环境一致性:
  时区: 本机 UTC+8  vs  IP≈UTC+9  ✅ 一致
  DNS : 解析器 China - China Mobile ... 
  ⚠️ DNS 出口与 IP 国家不一致：DNS=China，IP=Japan → 可能 DNS 泄漏/未走代理
  结论: ⚠️ 环境不一致，易被平台风控识别
```

## 平台适配度（IP 对社媒 / AI / 电商 / 流媒体的可用度）

不同平台对 IP 的风控差别很大：社媒、AI、支付普遍「杀机房、杀 VPN」，流媒体相对宽松。工具基于 IP 画像给每个平台类别一个**启发式风险**：

- 输入信号：机房/托管、代理、VPN、Tor、移动网络、滥用记录、AI 地区限制
- 输出：`🟢 适用 / 🟡 谨慎 / 🔴 易被风控` + 原因

示例（8.8.8.8 机房 IP）：
```
🟡 谨慎   社交媒体(X/FB/IG/TikTok)  机房/托管
🔴 易被风控 AI工具(OpenAI/Claude/Gemini)  机房/托管
🔴 易被风控 电商/支付(Amazon/PayPal)  机房/托管
```

> 这是**启发式初筛，不是平台真实判定**；各平台策略随时变，仅供「选 IP」参考。核心用途：避免「拿机房 IP 注册 AI/社媒 → 秒封」。

想更贴近真实风控：接 IPQS / Spur（住宅代理识别）+ 维护「各平台机房封禁强度」规则表 + 用实测成功率反馈校准阈值。

## 决策化输出 & 平台规则库

报表在「平台适配度」之后给出**使用建议**，直接回答能不能干这几件事：
```
✅ 推荐   爬虫/数据采集     机房 IP 适合高并发采集
⛔ 不建议  电商/支付        风控最严，机房/代理/滥用 IP 基本不可用
⚠️ 谨慎   注册社媒/AI账号   机房 IP 易触发手机验证
```

加 `--platforms` 看**具体平台**结论（内置规则库）：
```bash
python scripts/ipcheck.py 8.8.8.8 --platforms
```
内置平台：X、Facebook/Instagram、TikTok、Telegram、WhatsApp、Google、OpenAI/ChatGPT、Claude、Gemini、Midjourney、Amazon、PayPal、Binance、Netflix、Spotify。

平台风控强度（机房/VPN，供参考）：

| 平台 | 风控特点 |
|------|----------|
| PayPal / Binance | 最严，机房/代理基本不可用 |
| Facebook / Instagram / TikTok | 极严，新号 + 机房易封 |
| OpenAI / Claude | 杀机房 + 地区限制 |
| X / Google | 机房易触发手机验证 |
| Netflix | 封 VPN，需原生住宅 |
| Telegram | 对 VPN 较宽松 |

## 服务地区可用性（按 IP 所在国）

加 `--regions` 会按 IP 所在国列出各服务是否可用（近似，以官方为准）：
```bash
python scripts/ipcheck.py 8.8.8.8 --regions
```
覆盖：OpenAI/ChatGPT、Claude、Gemini、Netflix、Spotify、TikTok、PayPal、Binance、Steam。
例如美国 IP 会提示 `Binance ⛔ 受限（美国需 binance.us）`。

## 批量 / 导出 / 监控

```bash
# 批量：从文件读 IP（每行一个，# 注释）
python scripts/ipcheck.py --file ips.txt --brief

# 导出 CSV（UTF-8-BOM，Excel 直接打开）
python scripts/ipcheck.py --file ips.txt --csv result.csv

# 监控：目标 IP 关键属性(类型/代理/风险)变化
python scripts/ipcheck.py watch 8.8.8.8 --interval 60

# 监控：自身出口 IP 是否漂移（会话/代理稳定性）
python scripts/ipcheck.py watch --egress --interval 30
```

## 风险判定模型

- 外部分：取 Scamalytics 欺诈分、AbuseIPDB 置信度、Spamhaus 命中(≈90)、VirusTotal 恶意数换算 的较大值（0–100）。
- 免 key 举报信号：StopForumSpam 频率、blocklist.de 攻击数、IPsum 命中也会抬高风险。
- 信号分：Proxy +30、VPN +35、Hosting +10、Tor +60、Mobile −5。
- 综合风险分 = min(100, max(外部分, 信号分, 举报分))；等级 `<20` 干净、`20–49` 中低、`50–79` 中高、`≥80` 高。
- 源间冲突（例如 ip-api 说 proxy、proxycheck 说 no）会在报告「备注」中说明，并按可信源优先级取值。
- ⚠️ **以上权重是经验值，非校准概率**（见 `ipcheck.py` 顶部 `RISK_W_*` 常量）。综合分只用于排序/初筛，不代表真实风险概率。

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
