---
name: ip-reputation-check
description: >-
  多源 IP 信誉 / 风险检测技能。当用户给出一个 IP 并想了解它是否干净、是否代理/VPN/机房，
  或想看欺诈分、滥用记录，或需要测试出口 IP 在断开重连后是否稳定时使用本技能。
  触发词：查IP、IP检测、IP信誉、这个IP干不干净、ipinfo、iphub、scamalytics、abuseipdb、
  proxycheck、代理检测、VPN检测、机场IP、出口IP、IP稳定性、家宽/机房判断、fraud score、
  abuse confidence、IP risk、check my IP、is this IP clean。
  一次输入即可并发聚合 ipinfo.io、ip-api.com、ipwho.is、proxycheck.io、scamalytics.com，
  可选接入 iphub.info、abuseipdb.com，给出位置/ASN/代理标记/欺诈分/滥用置信度/综合风险判定。
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
- 可选 API Key（不配则自动跳过该源，其余照常）：
  - `IPHUB_API_KEY`（iphub.info，免费注册可得）
  - `ABUSEIPDB_API_KEY`（abuseipdb.com，免费 1000 次/天）
  - `IPINFO_TOKEN`（提高 ipinfo 限额，可选）
  - `SCAMALYTICS_USER` + `SCAMALYTICS_KEY`（走官方 API，缺省用网页解析）

## 核心用法（对 agent 的硬性步骤）

当用户给出 IP（一个或多个）时，运行：

```bash
python <skill_dir>/scripts/ipcheck.py check <IP> [<IP2> ...]
```

1. 直接执行，不要反问、不要先讲注意事项。
2. 把命令输出（报表）原样或整理成要点回复给用户。
3. 多 IP 时逐行/逐段列出，每个 IP 单独给结论。
4. 需要结构化数据或二次处理时加 `--json`。
5. 若某源被跳过（如未配 abuseipdb key），在结尾说明"缺哪个 key 可补哪个指标"，不要因此中止。

### 常用命令

```bash
# 单 IP 完整检测（人读报表）
python scripts/ipcheck.py check 8.8.8.8

# 多 IP + JSON（便于程序消费）
python scripts/ipcheck.py check 8.8.8.8 1.1.1.1 --json

# 只跑部分源（更快）
python scripts/ipcheck.py check 1.2.3.4 --only ipapi,proxycheck,scamalytics

# 看当前出口 IP
python scripts/ipcheck.py myip

# 连续采样，看出口 IP 是否漂移
python scripts/ipcheck.py stability --rounds 5 --interval 3

# 断开/重连前后对比（交互式，检测代理出口稳定性）
python scripts/ipcheck.py stability --interactive
```

## 输出字段说明（给 agent 解释用）

| 字段 | 含义 |
|------|------|
| 位置 / ASN / ISP | 来源 ip-api / ipinfo / ipwho.is，取单源整套以免跨源错配 |
| 代理 Proxy | proxycheck.io 优先，其次 iphub，最后 ip-api；源间冲突会在「备注」提示 |
| VPN | proxycheck 类型或 iphub block 判定 |
| 托管 Hosting | ip-api hosting、proxycheck 类型或云厂商组织关键字 |
| 欺诈分 | Scamalytics Fraud Score（0–100，越高越脏） |
| 滥用置信度 | AbuseIPDB confidence（0–100%，需 key） |
| 综合判定 | 综合外部分与代理/VPN/Tor 信号计算的 0–100 风险分与等级 |

判定等级：`<20 🟢 干净` / `20–49 🟡 中低` / `50–79 🟠 中高` / `≥80 🔴 高`。

## 稳定性检测说明

- `myip`：多源回显（icanhazip / ifconfig.me / ipinfo / ipify）取众数，确认当前出口 IP。
- `stability --rounds N`：定时多次采样，输出唯一 IP 集合，判断是否漂移。
- `stability --interactive`：先采样 → 提示用户断开/重连 → 再采样 → 对比是否一致，并对新 IP 做完整检测。

## 注意事项（写进报告时可选提示，不影响执行）

- 免费源有速率限制（ip-api 45 次/分、proxycheck 免 key 约 100 次/天），批量检测请加 `--interval` 或配 key。
- abuseipdb 网页版对脚本返回 403，必须走官方 API Key，否则该指标显示"需 key"。
- 判定为"代理/VPN/机房"不等于恶意；很多 CDN（如 Cloudflare、Google DNS）也会被标 hosting。

## 作为 skill 安装

- Claude Code：把本目录放到 `~/.claude/skills/ip-reputation-check/`
- Codex：放到 `~/.codex/skills/ip-reputation-check/`
- 通用 Agents（豆包 / Trae / 等）：放到 `~/.agents/skills/ip-reputation-check/`
- 本技能只依赖 `SKILL.md` 与 `scripts/ipcheck.py`，复制目录即生效。
