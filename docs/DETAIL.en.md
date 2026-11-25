> 状态: draft (草稿) · 归属: wave1 · 更新: 2026-11-25 · 里程碑: M5

# kore-plugin-firewall

This repository implements kore’s firewall/port management plugin (id `firewall`). Backend detection order is ufw → iptables → none (fixed paths, not PATH). Writes are protected by SSH, parameter allowlists and dry-run; IP allow/deny lists and brute-force bans are applied through the kernel root-action proxy — the plugin never escalates privileges or touches real host firewall rules.

语言：[简体中文](DETAIL.md) · [English](DETAIL.en.md) · [Español](DETAIL.es.md) · [Français](DETAIL.fr.md) · [Deutsch](DETAIL.de.md) · [Русский](DETAIL.ru.md) · [Português](DETAIL.pt.md)

## What it does

- **Protocol**: `kore.plugin.v1`, `lifecycle=lazy`, capability `system:admin`.
- **Methods**: `firewall.status` / `rules` / `allowPort` / `denyPort` / `deleteRule` / `ipList` / `ipAllow` / `ipDeny` / `ipRemove` / `recordFail` / `bruteSet`; bare verbs accepted.
- **Real probing**: `status` reports backend, availability, enabled state, default policy and rule count; `rules` returns the real rule list.
- **Fixed argv**: only `ufw` / `iptables` with fixed argument arrays — no shell, no host config file access.
- **Brute-force**: configurable threshold (5 failures → 10-minute ban by default); temporary timed bans applied automatically, zero tickers in the plugin.
- **Fail-closed**: without root or the kernel root-action channel, IP writes return `E_NEED_ROOT` with an actionable hint.

## Quick start

```bash
make check    # gofmt → vet → test
make build    # build the plugin binary
make dist     # produce the release tarball
```

The plugin is started on demand by the kore shell; `info.json` declares capabilities and `requires_kore`.

## Security and boundaries

Report vulnerabilities through [SECURITY.md](../SECURITY.md)

## Documentation map

[SECURITY.md](../SECURITY.md) — disclosure process.
[CONTRIBUTING.md](../CONTRIBUTING.md) — commit and release conventions.
[CHANGELOG.md](../CHANGELOG.md) — version history.
[info.json](../info.json) — capabilities and version declaration.

## FAQ

**Q: Do I need an account?**
No. There is no account, online verification or hidden telemetry; configuration is plain text.

**Q: Where do plugins live?**
Each plugin lives in its own `kore-plugin-<id>` repository, depending only on `kore/pkg/pluginapi`.

**Q: Where should I start?**
Read the protocol surface and method table in the README, then the capability declarations in `info.json`.
