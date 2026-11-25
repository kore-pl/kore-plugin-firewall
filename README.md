# kore-plugin-firewall

kore 的防火墙/端口管理插件：**真实探测后端、读取规则、管理 ufw 端口规则**。
执行面只调用固定 argv 的外部命令（`ufw` / `iptables`），不经过 shell、不读写宿主
配置文件、不启用或禁用防火墙。写操作统一经过 SSH 保护、参数白名单与 dry-run。

## 协议方法（kore.plugin.v1）

| 方法 | 入参 | 结果 | 写操作 |
| --- | --- | --- | --- |
| `kore.ping` | `{}` | `{status,uptime_s,goroutines,rss_kb}` | — |
| `kore.reload` | `{}` | `{ok:true,config_digest:""}`（无状态，空操作） | — |
| `kore.shutdown` | `{}` | `{ok:true}`，随后优雅退出 | — |
| `firewall.status` | `{}` | `{backend,available,enabled,default_in,rules_count,error}` | 只读 |
| `firewall.rules` | `{backend?}` | `{backend,rules[],count}` | 只读 |
| `firewall.allowPort` | `{port,proto?,from?,comment?,dry_run?}` | `{applied,dry_run,backend,command,rule}` | ufw |
| `firewall.denyPort` | `{port,proto?,from?,dry_run?}` | 同上（action=deny） | ufw |
| `firewall.deleteRule` | `{index,dry_run?}` | `{applied,dry_run,backend,command,deleted}` | ufw |
| `firewall.ipList` | `{}` | `{rules[],count,brute,backend,error?}` | 只读 |
| `firewall.ipAllow` | `{mode,ip,comment?,dry_run?}` | `{applied,dry_run,command,rule}` | nft root-action |
| `firewall.ipDeny` | 同上 | 同上（黑名单） | nft root-action |
| `firewall.ipRemove` | `{id,dry_run?}` | 同上 | nft root-action |
| `firewall.recordFail` | `{ip}` | `{ip,failures,banned,ban_until?,threshold}` | nft root-action（达阈值时） |
| `firewall.bruteSet` | `{enabled?,threshold?,ban_min?}` | `{enabled,threshold,ban_min}` | 配置（落盘） |

方法名同时接受 `firewall.<verb>` 与裸 `<verb>`。未知方法返回 `E_NOTFOUND`。

### firewall.status

- 后端探测优先级：`ufw` → `iptables` → `none`（固定路径优先，不依赖插件进程 PATH）。
- `ufw` 用 `ufw status verbose`：`Status:` → `enabled`，`Default:` 的 `(incoming)` →
  `default_in`（`allow`→`accept`、`deny`→`deny`、`reject`→`reject`），规则表格行数 →
  `rules_count`（含 v6 条目）。
- `iptables` 用 `iptables -S`：`-P INPUT` → `default_in`，可归一的 INPUT 规则数 →
  `rules_count`；iptables 无全局开关，规则集存在即 `enabled=true`。
- **探测失败不返回协议错误**：`available=false`，`error` 写明原因（例如非 root）。
  `enabled / default_in / rules_count` 仅在 `available=true` 时可信。
- 本插件**不提供**启用/禁用/重置防火墙的方法（避免误操作锁死 SSH）。

### firewall.rules

- `backend` 省略时自动探测；显式值只接受 `ufw` / `iptables`，其余 `E_INVALID`；
  显式后端未安装返回 `E_UNSUPPORTED`。
- `ufw`：解析 `ufw status numbered`，保留编号（删除时作为 `index`）。ufw inactive 时
  没有编号输出，返回空列表（不报错）。
- `iptables`：**只读 INPUT 链**。`ACCEPT/DROP/REJECT` 归一为
  `allow/deny/reject`；跳转自定义链（如 `DOCKER-USER`）无法归一到三值动作，跳过；
  `-j` 之外的非 TCP/UDP 协议（如 icmp）保留真实协议名，不伪装成 `any`；
  `-i` 接口名与目的地址限定注解到 `comment` 的 `[iface=…]` / `[to=…]` 中。
- 统一规则结构：

  ```json
  {"index":1,"action":"allow","direction":"in","proto":"tcp","port":22,
   "from":"0.0.0.0/0","comment":"ssh"}
  ```

  `port` 单端口输出 JSON 数字，区间/多端口（`"22:80"`、`"80,443"`）或全端口空值输出
  字符串；`direction` 为 `in|out`（ufw 的 `FWD` 按入站侧归一，保证 SSH 护栏目不漏判）；
  ufw 的 `LIMIT` 是限速放行，归为 `allow`；`from` 的 `Anywhere` → `0.0.0.0/0`、
  `Anywhere (v6)` → `::/0`。

### firewall.allowPort / denyPort（仅 ufw）

- `port` 必须是 1–65535 的整数；`proto` 缺省 `tcp`，只接受 `tcp|udp`；
  `from` 缺省 `any`，只接受 `any`、合法 IP 或 CIDR（用 `net.ParseIP/ParseCIDR` 白名单
  校验，拒绝主机名与任何 shell 元字符）；`comment` ≤64 字符，字符白名单。
- 固定 argv（逐项参数，无 shell）：

  ```
  ufw allow proto tcp from any to any port 18080 comment kore-web
  ufw deny  proto udp from 10.0.0.0/8 to any port 5353
  ```

- 返回 `applied=true` 表示 ufw 命令执行成功（exit 0）；`command` 是实际执行的 argv。
- **dry-run**：`dry_run=true` 时只做参数校验与命令构造，返回 `applied=false`、
  `dry_run=true` 与完整 `command`，**不执行任何外部命令**（包括不读取 ufw 状态）。

### firewall.deleteRule（仅 ufw）

- `index` 来自 `ufw status numbered`；删除命令固定为 `ufw --force delete <index>`。
- 删除前**先回读规则内容**：编号不存在 → `E_NOTFOUND`；目标是「入站 + allow + 覆盖
  SSH 端口」的规则 → `E_UNAUTHORIZED`（见下）。
- `dry_run=true` 只返回命令（仍需回读规则以完成 SSH 护栏目判断），不执行删除。
- 只有 ufw 后端支持删除；iptables 只读。

### `firewall.ipList / ipAllow / ipDeny / ipRemove`（IP 白/黑名单）

- 白名单（allow）优先放行、黑名单（deny）丢弃：数据面为 kore 自有 nft 表 `kore_fw`，集合 `allow4` / `deny4`，base chain `input` 的链规则为「白名单 accept → 黑名单/封禁 drop」（chain `policy accept`，只丢命中规则的包）。
- `ip` 只接受 IPv4 地址或 CIDR（`net.ParseIP/ParseCIDR` 校验，拒绝主机名与注入字符）；CIDR 会归一化成网络地址（`10.1.2.3/8` → `10.0.0.0/8`）后再落库与下发。`comment` ≤64 字符，与端口规则同一白名单。
- 写操作走 ADR-0018 内核 root-action 通道（6 条 nft 动作，`root_actions` 共 13 条，未超内核协议上限 16 条）：建表 + 建两个集合 + base chain + 两条链规则压进单个 `nft-init`（6 条语句，nft argv 用空格拼行 + 独立 `;` 分句，内核按语句级形状表逐句校验）。插件自身不提权、不直接改宿主防火墙。
- 非 root 且内核 root-action 通道不可用时 `E_NEED_ROOT`（HTTP 403）+ `hint`（fail-closed，绝不静默成功）；`dry_run=true` 只返回命令、不下发。
- 规则落 `<KORE_STATE_DIR>/iplist.json`（0600 原子写），`ipList` 回读含规则、防爆破配置与后端探测结果。
- **表是运行态**：nft 表不跨宿主重启持久化。插件进程内首次写操作会先探活（`nft-list`），表缺失则重建并把 `iplist.json` 里的规则回灌（过期封禁跳过），避免「界面有、宿主没有」。

### `firewall.bruteSet / recordFail`（防爆破）

- `bruteSet` 配置 `enabled` / `threshold`（1–1000，默认 5）/ `ban_min`（1–1440 分钟，默认 10），落盘并热生效，无 ticker。
- `recordFail{ip}` 记一次登录失败（10 分钟滑动窗口）；达到阈值时自动下发一条带 `timeout` 的元素到 nft 集合 `deny4`（黑名单与临时封禁共用同一集合），到期由内核超时自动移除、插件零 ticker；已封禁 IP 重复调用不重复封禁，封禁后失败计数清零。
- 审计接口的 `Detail.ip` 已脱敏，**不能**当封禁数据源；调用方需传精确来源 IP。当前闭环为「管理员录入 + UI 配置」，未来内核登录失败 hook 可在不插件侧改接口的前提下接入。

### 已知边界（0.3.0）

- **只支持 IPv4**（地址与 CIDR）：内核协议的 `root_actions` 上限是 16 条，ufw/iptables 已占 7 条，再为 allow6/deny6 各立「建集合 + 增 + 删」动作会超限。IPv6 地址/网段传入时返回 `E_UNSUPPORTED` 并提示改用 ufw 规则（`ufw allow from 2001:db8::1`），不会静默塞进 IPv4 集合。
- **真实下发需要 root**：非 root 的 kored 只能 dry-run + `E_NEED_ROOT`；本仓 CI/开发机（非 root）不验证真实 nft 写入，证据边界见下文。

## 安全护栏

| 护栏 | 行为 |
| --- | --- |
| deny 22 | **拒绝**：`拒绝屏蔽 SSH 端口 22：这会导致你无法再连接到服务器。如确实需要，请先确认有其他登录方式`（`E_UNAUTHORIZED`）；`dry_run` 同样被拒 |
| `KORE_SSH_PORT` | 逗号分隔的额外 SSH 端口，始终并入 22 一起保护；非法取值**启动即失败**，不静默退回默认 |
| 删除 SSH 放行规则 | 入站 + `allow` + 端口覆盖 SSH 端口 → `E_UNAUTHORIZED`，不执行删除；删除 `deny`/`out` 规则不受影响 |
| 写操作能力 | 三个写方法要求 `system:admin`（插件侧纵深校验，内核另有调用前授权） |
| 参数白名单 | 端口 1–65535、proto 仅 tcp/udp、from 仅 any/IP/CIDR、comment 字符与长度受限 |
| 命令注入 | 固定 argv、无 shell、不拼接字符串；命令统一 `LC_ALL=C` 执行 |
| 启用/禁用 | **不在方法面**：插件永远不启用、禁用或重置防火墙 |
| 后端范围 | 写操作只支持 ufw；iptables 只读 INPUT 链 |

被拒绝的写操作不会构造或执行任何外部命令（护栏在命令执行前完成）。

## 为什么不做 enable/disable

防火墙配置错误会直接锁死 SSH 会话。本插件把「启用/禁用/重置」排除在方法面之外，
只提供端口级 allow/deny/delete；启用防火墙应由运维在带外环境人工完成。

## 测试与证据边界

```sh
gofmt -l .
go vet ./...
go test -timeout 200s ./...
make build && make dist
```

- `internal/fwop`：参数白名单、SSH 保护（deny 22 / 自定义端口 / 删除放行规则）、
  dry-run 不执行、`ufw status verbose|numbered` 与 `iptables -S` fixture 解析、
  capability 门禁、后端选择与错误分类。
- `tests/fault/`：kill -9 / 超时 / 磁盘满 / cgroup 四类故障注入，覆盖 rules /
  allowPort / denyPort / deleteRule，断言 `E_UPSTREAM` / `E_INTERNAL` /
  `E_UNSUPPORTED` 与无故障 sanity。
- `tests/e2e/`：真实插件二进制 + 假内核 UDS，只做**只读 + dry-run**：
  `status` / `rules` 真实执行，`allowPort{dry_run:true}` 返回命令但不执行，
  前后 `ufw status verbose`、`iptables -S` 与 `/etc/ufw/user*.rules` 元信息 diff 为空，
  `denyPort{22}` 被拒。**E2E 绝不启用 ufw、绝不修改规则。**

真实写路径（非 dry-run 的 allow/deny/delete）只由单元测试与 fixture 覆盖，
本轮未在真机执行——这是刻意的安全选择，不是遗漏。

## 构建与确定性

`make dist` 用固定 mtime/owner 的 tar + `gzip -9n`。`size_bytes` 采用「迭代 + 2-cycle
检测」收敛：gzip 压缩长度对数字内容敏感，可能出现 ±1 字节往返；脚本检测到往返后取
较小值固定并重建，保证包内清单与源 `info.json` 一致，且重复构建 / 任意起点重建的
sha256 相同（声明值与实际包体允许 ≤2 字节偏差）。

<!-- oss:begin -->
## 开源与贡献

[![CI](https://github.com/kore-pl/kore-plugin-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/kore-pl/kore-plugin-firewall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go 1.26](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](go.mod)

本仓库是 **kore** 的 `防火墙/端口管理插件`（id `firewall`），独立仓库、独立版本线、独立 CI：GitHub Actions 只手动触发（`workflow_dispatch`），按版本 tag 自动触发在 Gitea Actions（`.gitea/workflows/ci.yml`，push `v*` + 手动）。内核与协议见 [kore](https://github.com/kore-pl/kore)。

- **许可**：MIT（inbound = outbound，不要求 CLA）；提交用 `git commit -s` 签 DCO。
- **贡献**：[CONTRIBUTING.md](CONTRIBUTING.md)（构建、门禁、发版、边界）。
- **安全**：[SECURITY.md](SECURITY.md)——漏洞不要开公开 issue。
- **行为准则**：[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。
- **兼容性**：`protocol: kore.plugin.v1` · `requires_kore: >=0.1.0 <0.2.0` · `lifecycle: lazy` · 深度等级 `production`。
- **验证方式**：本地 `make check` 优先（GitHub CI 只手动触发，Gitea CI 按版本 tag 触发；发布前 `make dist` 连跑两次核对 sha 一致）。
- **发布产物**：`make dist` → `dist/firewall-0.3.0.tar.gz` + `.sha256`（位级可复现，连跑两次 sha 相同）。
- **相关仓库**：[索引 kore-plugins](https://github.com/kore-pl/kore-plugins) · [协议文档](https://github.com/kore-pl/kore/blob/main/docs/PLUGIN-PROTOCOL.md) · [SDK 指南](https://github.com/kore-pl/kore/blob/main/docs/PLUGIN-SDK.md)

<!-- oss:end -->
