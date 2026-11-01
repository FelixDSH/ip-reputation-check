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
| iphub.info | block 代理等级 | 是：`IPHUB_API_KEY` |
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
ipcheck check <IP...> [--json] [--only a,b,...] [--timeout 12] [--no-color]
ipcheck myip [--json]
ipcheck stability [--rounds N] [--interval S] [--interactive] [--json] [--only ...]
```

`--only` 可选值：`ipinfo,ipapi,ipwhois,proxycheck,scamalytics,iphub,abuseipdb`

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
