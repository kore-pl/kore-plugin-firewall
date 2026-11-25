> 状态: draft · 归属: wave1 · 更新: 2026-11-25 · 里程碑: M5

# kore-plugin-firewall

本仓实现 kore 的防火墙/端口管理插件（id `firewall`）。后端探测优先级 ufw → iptables → none（固定路径，不依赖 PATH）。写操作统一经过 SSH 保护、参数白名单与 dry-run；IP 白/黑名单与防爆破规则经内核 root-action 代理下发，插件不提权、不碰宿主防火墙真实规则。

语言：[简体中文](DETAIL.md) · [English](DETAIL.en.md) · [Español](DETAIL.es.md) · [Français](DETAIL.fr.md) · [Deutsch](DETAIL.de.md) · [Русский](DETAIL.ru.md) · [Português](DETAIL.pt.md)

## 它做什么

- **协议面**：`kore.plugin.v1`，`lifecycle=lazy`，能力声明 `system:admin`。
- **方法**：`firewall.status` / `rules` / `allowPort` / `denyPort` / `deleteRule` / `ipList` / `ipAllow` / `ipDeny` / `ipRemove` / `recordFail` / `bruteSet`；方法名同时接受裸动词。
- **真实探测**：`status` 报告后端、可用性、启用状态、默认策略与规则数；`rules` 返回真实规则清单。
- **固定 argv**：执行面只调用 `ufw` / `iptables` 固定参数数组，不经 shell、不读写宿主配置文件。
- **防爆破**：阈值可配（默认登录失败 5 次封禁 10 分钟）；达阈值自动下发带 timeout 的临时封禁，插件零 ticker。
- **fail-closed**：非 root 且无内核 root-action 通道时 IP 写操作返回 `E_NEED_ROOT` + 可操作提示。

## 快速开始

```bash
make check    # gofmt → vet → test
make build    # 构建插件二进制
make dist     # 产出发布 tarball
```

插件由 kore 主壳按需拉起；`info.json` 声明能力与 `requires_kore` 区间。

## 安全与边界

漏洞披露走 [SECURITY.md](../SECURITY.md)

## 文档导航

[SECURITY.md](../SECURITY.md) — 漏洞披露流程。
[CONTRIBUTING.md](../CONTRIBUTING.md) — 提交与发版规范。
[CHANGELOG.md](../CHANGELOG.md) — 版本变更记录。
[info.json](../info.json) — 能力与版本声明。

## 常见问题

**问：需要注册账号才能用吗？**
不需要。没有账号、无联网校验、无隐藏上报；配置明文，看得懂也改得动。

**问：插件住在哪？**
插件住在各自 `kore-plugin-<id>` 仓，只依赖 `kore/pkg/pluginapi`。

**问：我该先读什么？**
先看 README 的协议面与方法表，再看 `info.json` 的能力声明。
