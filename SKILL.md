---
name: ip-reputation-check
description: >-
  多源 IP 信誉 / 风险检测技能。当用户给出一个 IP 并想了解它是否干净、是否代理/VPN/机房，
  或想看欺诈分、滥用记录，或需要测试出口 IP 在断开重连后是否稳定时使用本技能。
  触发词：查IP、IP检测、IP信誉、这个IP干不干净、ipinfo、iphub、scamalytics、abuseipdb、
  proxycheck、代理检测、VPN检测、机场IP、出口IP、IP稳定性、家宽/机房判断、fraud score、
  abuse confidence、IP risk、check my IP、is this IP clean。
  一次输入即可并发聚合 ipinfo.io、ip-api.com、ipwho.is、proxycheck.io、scamalytics.com，
  可选接入 iphub.info、abuseipdb.com、Spamhaus DNSBL、VirusTotal，给出位置/ASN/代理标记/欺诈分/滥用置信度/综合风险判定，
  并标注每个维度的置信度（高/中/低）。定位为「多源聚合初筛」，非权威风控判定。
license: MIT
---

# ip-reputation-check

一个纯 Python 标准库实现的 IP 信誉检测技能。**任意 agent 加载后，用户只需在对话里给一个 IP，
执行一条命令即可得到多源聚合的检测报告。**

## 何时使用

- 用户给出 IP，问「这个 IP 怎么样 / 干不干净 / 是不是代理 / 是不是机场」。
- 需要核对某个 IP 的地理、ASN、ISP、机房/住宅属性。
- 需要 Scamalytics 欺诈分、AbuseIPDB 滥用记录、iphub 代理判定。
- 需要测试「断开重连后出口 IP 是否保持不变」（代理/VPN 稳定性）。

## 环境要求

- Python 3.8+（无第三方依赖）。
- 可选 API Key（不配则对应源自动降级/跳过，其余照常）：
  - `IPHUB_API_KEY`（iphub.info，免费注册；不配则走网站游客接口，机房/VPN 出口可能触发 Turnstile）
  - `ABUSEIPDB_API_KEY`（abuseipdb.com，免费 1000 次/天；网页版直连会 403，必须用 key）
  - `IPINFO_TOKEN`（提高 ipinfo 限额，可选）
  - `SCAMALYTICS_USER` + `SCAMALYTICS_KEY`（走官方 API，缺省用网页解析）
  - `IPHUB_TURNSTILE_TOKEN`（人工过 iphub 验证后拿到的 token，可选）
  - `VIRUSTOTAL_API_KEY`（可选，70+ 引擎恶意判定）
  - 地理：免 key 的 **DB-IP** 已内置；最权威可接 **MaxMind GeoLite2**：`python scripts/setup_geoip.py --license-key KEY`（需 `pip install maxminddb`）

## 核心用法（对 agent 的硬性步骤）

当用户给出 IP（一个或多个）时，运行：

```bash
python <skill_dir>/scripts/ipcheck.py <IP> [<IP2> ...]
```

（也支持显式 `check` 子命令；直接给 IP 即可。）

1. 直接执行，不要反问问、不要先讲注意事项。
2. 把命令输出（报表）原样或整理成要点回复给用户；想更精简可加 `--brief`（一行式）。
3. 多 IP 时逐行/逐段列出，每个 IP 单独给结论。
4. 需要结构化数据或二次处理时加 `--json`。
5. 若某源被跳过（如未配 abuseipdb key），在结尾说明"缺哪个 key 可补哪个指标"，不要因此中止。

### 常用命令

```bash
# 单/多 IP 完整检测（直接给 IP 即可）
python scripts/ipcheck.py 8.8.8.8
python scripts/ipcheck.py 8.8.8.8 1.1.1.1 --brief   # 一行式简报
python scripts/ipcheck.py 8.8.8.8 --json            # 结构化输出

# 只跑部分源（更快）
python scripts/ipcheck.py 1.2.3.4 --only ipapi,proxycheck,scamalytics

# 看当前出口 IP + 环境一致性（时区/DNS vs IP）
python scripts/ipcheck.py myip
python scripts/ipcheck.py <IP> --env      # 检查某 IP 时附带环境一致性(防关联指纹)

# 检测完打开 abuseipdb/iphub 网页（IP 已自动带入，人工核验）
python scripts/ipcheck.py 8.8.8.8 --open
python scripts/ipcheck.py open 8.8.8.8 --all

# 看当前出口 IP
python scripts/ipcheck.py myip

# 连续采样，看出口 IP 是否漂移
python scripts/ipcheck.py stability --rounds 5 --interval 3

# 断开/重连前后对比（交互式，检测代理出口稳定性）
python scripts/ipcheck.py stability --interactive

# 团队共用：走自建网关（客户端无需任何源 key，key 只在服务端）
python scripts/ipcheck.py check <IP> --gateway http://GATEWAY:8787
```

> 分发/多人使用：**不要把个人 key 写进 skill**。免 key 的 5 个源已够用；需要 iphub/abuseipdb 精度时，
> 每人用自己的免费 key（BYOK），或由团队跑一台 `scripts/gateway.py` 统一持 key+缓存+限流，其他人零 key 访问。

## 输出字段说明（给 agent 解释用）

| 字段 | 含义 |
|------|------|
| 位置 / ASN / ISP | 来源 ip-api / ipinfo / ipwho.is，取单源整套以免跨源错配 |
| IP 类型 | 住宅 / 移动(4G/5G) / 机房云主机 / 企业 / 教育 / 政府 / Tor / VPN / 代理 |
| 代理 Proxy | proxycheck.io 优先，其次 iphub，最后 ip-api；源间冲突会在「备注」提示 |
| VPN | proxycheck 类型或 iphub block 判定 |
| 托管 Hosting | ip-api hosting、proxycheck 类型或云厂商组织关键字 |
| 欺诈分 | Scamalytics Fraud Score（0–100，越高越脏） |
| 滥用置信度 | AbuseIPDB confidence（0–100%，需 key） |
| 综合判定 | 综合外部分与代理/VPN/Tor 信号计算的 0–100 风险分与等级 |
| 置信度 | 地理/代理/VPN/托管/滥用 各自的 高/中/低：源等级 × 多源一致度。低=单一源或有冲突；滥用"低"≠干净 |
| 平台适配度 | 该 IP 对 社媒/AI/电商/流媒体/注册 的可用度（🟢适用/🟡谨慎/🔴易被风控），启发式，非平台真实判定 |

判定等级：`<20 🟢 干净` / `20–49 🟡 中低` / `50–79 🟠 中高` / `≥80 🔴 高`。

## 稳定性检测说明

- `myip`：多源回显（icanhazip / ifconfig.me / ipinfo / ipify）取众数，确认当前出口 IP。
- `stability --rounds N`：定时多次采样，输出唯一 IP 集合，判断是否漂移。
- `stability --interactive`：先采样 → 提示用户断开/重连 → 再采样 → 对比是否一致，并对新 IP 做完整检测。

## 注意事项（写进报告时可选提示，不影响执行）

- 免费源有速率限制（ip-api 45 次/分、proxycheck 免 key 约 100 次/天），批量检测请加 `--interval` 或配 key。
- **人机验证**：ipinfo / ip-api / ipwho.is / proxycheck / scamalytics 都是干净的 JSON 接口，无验证码；只有 **iphub 游客接口**（可能弹 Cloudflare Turnstile）和 **abuseipdb 网页版**（403）会拦。对策按优先级：① 配免费 `IPHUB_API_KEY` / `ABUSEIPDB_API_KEY`（彻底免验证码，首选）；② `python scripts/iphub_browser.py <IP>` 用真实 Chrome 人工过验证；③ 设 `IPHUB_TURNSTILE_TOKEN` 或接打码服务。详见 README「人机验证」章节。
- 判定为"代理/VPN/机房"不等于恶意；很多 CDN（如 Cloudflare、Google DNS）也会被标 hosting。
- **滥用举报不止 AbuseIPDB**：AbuseIPDB 需免费 key；免 key 的 StopForumSpam / blocklist.de / IPsum / Spamhaus DNSBL 已自动包含并计入风险。想直接看 AbuseIPDB 网页用 `python scripts/ipcheck.py open <IP>`（自动带入 IP）。
- **不是权威**：本工具是多源聚合初筛，按源等级（A 权威/B 专业/C 社区）和一致度给置信度。汇报时要如实说明置信度，不要把它当风控定论。
- **平台适配度是启发式**：🟢/🟡/🔴 只是「机房/VPN/代理/滥用/AI地区限制」等信号的加权初筛，不代表平台真实判定；各平台策略随时变。

## 作为 skill 安装

- Claude Code：把本目录放到 `~/.claude/skills/ip-reputation-check/`
- Codex：放到 `~/.codex/skills/ip-reputation-check/`
- 通用 Agents（豆包 / Trae / 等）：放到 `~/.agents/skills/ip-reputation-check/`
- 本技能只依赖 `SKILL.md` 与 `scripts/ipcheck.py`，复制目录即生效。
