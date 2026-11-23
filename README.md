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

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go 1.26](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](go.mod)

本仓库是 **kore** 的 `防火墙/端口管理插件`（id `firewall`），独立仓库、独立版本线。内核与协议见 [kore](https://github.com/kore-pl/kore)。

- **许可**：MIT（inbound = outbound，不要求 CLA）；提交用 `git commit -s` 签 DCO。
- **贡献**：[CONTRIBUTING.md](CONTRIBUTING.md)（构建、门禁、发版、边界）。
- **安全**：[SECURITY.md](SECURITY.md)——漏洞不要开公开 issue。
- **行为准则**：[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。
- **兼容性**：`protocol: kore.plugin.v1` · `requires_kore: >=0.1.0 <0.2.0` · `lifecycle: lazy` · 深度等级 `production`。
- **验证方式**：本地 `make check`（插件仓不配 CI；发布前 `make dist` 连跑两次核对 sha 一致）。
- **发布产物**：`make dist` → `dist/firewall-0.2.4.tar.gz` + `.sha256`（位级可复现，连跑两次 sha 相同）。
- **相关仓库**：[索引 kore-plugins](https://github.com/kore-pl/kore-plugins) · [协议文档](https://github.com/kore-pl/kore/blob/main/docs/PLUGIN-PROTOCOL.md) · [SDK 指南](https://github.com/kore-pl/kore/blob/main/docs/PLUGIN-SDK.md)

<!-- oss:end -->
