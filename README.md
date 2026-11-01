# ip-reputation-check

**中文** | [English](README.en.md)

> 多源 IP 查询 + 当前出口验证 + 面向用途的节点体检。给一个 IP 或一个节点，快速得到**可核对的多维证据**与**常用站点可达性**。
>
> ⚠️ 定位：**多源聚合初筛 + 证据分级**，不是权威风控/安全鉴定；免费源精度有限，重要决策请交叉验证或用商业 API（MaxMind / IPQualityScore / Spur / VirusTotal / Spamhaus 等）。

完整示例输出见 [examples/demo.txt](examples/demo.txt)（由当前代码生成，非手写）。

## 极简用法

```bash
python scripts/ipcheck.py 8.8.8.8            # 直接给 IP（默认零配置）
python scripts/ipcheck.py 8.8.8.8 --brief    # 一行式简报
```

默认免 key 即可出：位置 / ASN / 机房·代理·VPN / 欺诈分 / 免 key 滥用名单 / 规则提示分 / 置信度。需要更多精度时可选配自己的免费 key（见「可选 Key」）。

## 核心能力

- **多源聚合**（17 个源）：地理、ASN、代理/VPN/机房、欺诈分、滥用名单、RDAP 登记、BGP 路由、Tor 官方出口。
- **证据可追溯**：每字段列出「适用来源 + 支持/反对 + 强度」；登记(RDAP) 与路由(BGP) 分开；`标记为VPN ≠ 实际是VPN`。
- **不误导**：数据不足/空响应 → `⚪ 无法判定`（绝不判"干净"）；DNSBL 临时失败→未知；Fake-IP→DoH 兜底但只信命中；私有/保留地址本地跳过。
- **实测（可选）**：`probe / node / compare / history` 从出口或代理真实只读探测；严格区分"规则推算"与"实测"。
- **实用运维**：批量 `--file`、CSV、监控 `watch`、源健康 `health`、来源级缓存、一键自检 `selfcheck`。

## 命令速查

```bash
# 被动查询
python scripts/ipcheck.py check <IP...> [--file F] [--csv out.csv] [--json] [--brief] \
       [--env] [--regions] [--no-platforms] [--refresh] [--interval S] [--only ...] [--gateway URL]

# 实测（需从该出口/代理发起；默认关）
python scripts/ipcheck.py probe  [--proxy URL] [--expect-ip IP] [--only google,openai,x,...] [--json]
python scripts/ipcheck.py node   [--proxy URL] [--expect-ip IP] [--scenario browse|ai|stream|account|call|general] [--samples 3] [--save] [--json]
python scripts/ipcheck.py compare --nodes "http://p1,http://p2" [--scenario ai] [--json]
python scripts/ipcheck.py history [--node X] [--scenario ai] [--last 5]

# 运维
python scripts/ipcheck.py myip            # 出口 IP + 时区/DNS 环境一致性
python scripts/ipcheck.py health          # 逐源健康检查（可用性/延迟）
python scripts/ipcheck.py open <IP>       # 打开已填 IP 的 abuseipdb/iphub 网页
python scripts/ipcheck.py stability [--rounds N] [--interactive]
python scripts/ipcheck.py watch [IP...] [--egress] [--interval 60]
python scripts/selfcheck.py               # 一键自检：全部离线测试 + 在线冒烟
```

`--only` 源：`ipinfo,ipapi,ipwhois,proxycheck,scamalytics,iphub,abuseipdb,stopforumspam,blocklistde,ipsum,spamhaus,virustotal,dbip,maxmind,rdap,ripe_bgp,tor_exit`

## 输出说明

| 项目 | 含义 |
|---|---|
| 位置 / ASN / ISP / 云厂商 | 地理数据库 + 登记/路由；云厂商=按 ASN/组织名推断（非已确认用途） |
| IP 类型 | 住宅 / 移动 / 机房·云 / 企业 / 教育 / 政府 / Tor / VPN / 代理；仅按可用证据判定 |
| 代理 / VPN / 托管 / Tor | **数据库/规则标签，非实测**（"标记为VPN"≠"实际是VPN"） |
| 欺诈分 / 滥用置信度 | Scamalytics Fraud Score；AbuseIPDB（需 key）；Spamhaus（DNSBL，区分恶意/策略名单/PBL） |
| 规则提示分 | 经验加权**规则分，非概率**；数据不足=无法判定 |
| 置信度 + 证据强度 + 字段来源 | 源等级×一致度；每字段支持/反对来源；按字段适用来源 |
| 平台/站点适配度 | 规则推算，非实测；红灯=易触发风控，不代表一定不可用/会封号 |
| 使用建议 | 能否注册/养号/爬虫/支付/流媒体（启发式，随证据匹配） |

## 数据源

| 源 | 提供 | Key |
|---|---|---|
| ipinfo / ip-api / ipwho.is | 地理 / ASN（ip-api 含 proxy/hosting 标记） | 免 |
| proxycheck | 代理 / VPN / 类型 | 免（有日限） |
| scamalytics | 欺诈分（网页解析/API） | 免 / 可选 API |
| iphub | 代理分级 | 游客免（可能 Turnstile）/ 推荐 key |
| AbuseIPDB | 滥用置信度 | 需 `ABUSEIPDB_API_KEY` |
| StopForumSpam / blocklist.de / IPsum | 垃圾信息 / 攻击 / 聚合黑名单 | 免 |
| Spamhaus DNSBL | SBL/XBL/DROP=恶意；PBL=发信策略 | 免（DNS） |
| VirusTotal | 多引擎 | 可选 `VIRUSTOTAL_API_KEY` |
| DB-IP / MaxMind GeoLite2 | 地理（后者最权威，本地库） | 免 / 免费 License + maxminddb |
| RDAP / RIPEstat / Tor 官方出口 | 登记 / 路由 / Tor 名单 | 免 |

来源可能共享上游：**数量 ≠ 独立证据**；无法证明独立按"未知"处理（详见下方置信度）。

## 置信度与证据

- 源分 A（权威/商业：ipinfo/Spamhaus/VirusTotal/MaxMind/DB-IP/RDAP/RIPEstat/Tor）、B（专业）、C（社区/聚合）。
- 每字段**只采用适用来源**（地理只用地基库；代理/VPN 用专用库；Tor 用官方名单；滥用用名单/社区）。JSON `evidence` 含 `sources/applicability/level`。
- **独立性未知**：无 A 级来源支持时，多个 B/C 一致最高只到「中」（**这是临时保守评级，不代表已解决独立性**）。
- "高/中/低"是**证据分级**，不是统计概率；不输出"准确率/封号概率"。

## 缓存与时间

按来源缓存原始结果（**不缓存最终判断**，升级规则后重新聚合）。键=解析器版本+来源+规范化IP。
`fetched_at / data_time / expires_at / served_at / cache_status`；`--refresh` 强制重查并穿透名单级缓存；过期在允许回退期内→可用但标注，超期→仅历史不参与判断；名单源用名单实际取得时间；不含密钥。

## 实测边界（重要）

- 必须**从该 IP 的出口**发起（`--proxy` 指定代理）；出口≠目标会告警，结论只归因实际出口。
- 只测**网页/公开 API 端点**，未验证 App 登录/上传/推送；请求耗时是"经该代理的请求表现"，**非线路 ping/丢包**。
- 状态保守：连接成功(功能未验证) / 明确地区限制 / 人机验证(≠封号) / 需登录 / 访问拒绝(原因不明) / 限流 / 连接失败。
- 代理可能按域名/IPv6 分流：出口回显匹配是**必要条件非充分条件**。

## 环境要求

- 基础：**Python 3.8+，无第三方依赖**；Windows 免安装用 `dist/ipcheck.exe`。
- 可选：`pip install maxminddb`（配 MaxMind 库）；`--browser`/`iphub_browser.py` 需 Playwright+Chrome。
- 可选 Key：`IPHUB_API_KEY` / `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` / `IPINFO_TOKEN` / `SCAMALYTICS_USER`+`SCAMALYTICS_KEY` / `GEOIP2_MMDB` / `IPCHECK_GATEWAY` / `IPCHECK_PROXY` / `IPCHECK_CACHE` / `IPCHECK_HISTORY`。

## 项目结构

```
scripts/
├── ipcheck.py            # 入口 shim（ipcheck.<name> 均可用）
├── selfcheck.py          # 一键自检
└── ipcheck_lib/
    ├── constants.py  http.py  sources.py  scoring.py
    ├── render.py  env.py  csvio.py  probe.py  cache.py  cli.py
    └── fixtures/     # 固定样本（含 abnormal 异常页）
gateway.py / setup_geoip.py / iphub_browser.py   # 独立工具
tests/  test_core(test_cache/test_counterexamples/test_fixtures/test_contract/test_docs/test_consistency)
```

## 合规

自动探活须遵守 服务条款 / API 政策 / 数据许可；`robots.txt` 仅爬虫场景适用、不等于自动化授权；免费源有速率与商用/再分发条款；代理凭据不进日志/报告。

## 测试

```bash
python scripts/selfcheck.py     # 全部离线测试 + 在线冒烟（推荐）
```
离线套件：core / cache / counterexamples（审计反例）/ fixtures（固定样本）/ contract（异常页与坏数据）/ docs（文档漂移）/ consistency（类型×文案）。CI 覆盖 Python 3.8/3.10/3.12 + Windows。

## 能力边界

- 可信度分项：网络登记/路由/ASN 较高；国家对、城市 50–80%；代理/VPN 覆盖不全；**滥用"未命中"证明力弱**；站点适配为规则推算，非实测。
- 不能仅凭 IP 判断"是否独享住宅 / 会不会封号 / 长期是否稳定"。
- 无吞吐/丢包、无 App 功能实测。

## License

MIT © 2026 FelixDSH
