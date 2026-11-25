# Changelog

## 0.3.0 (2026-11-25)

- feat(iplist): 补竞品清单条目 5——IP 白名单/黑名单与防爆破。新增 6 个方法：`ipList` / `ipAllow` / `ipDeny` / `ipRemove` / `recordFail` / `bruteSet`；规则区分 allow/deny/ban，支持 IPv4 地址与 CIDR（CIDR 归一化为网络地址），白名单优先放行避免误封
- fix(root-action): `root_actions` 从 28 条收敛到 13 条（内核协议上限 16 条，原方案会导致 `store/install` 校验失败、包根本装不上）；建表 + 两个集合 + base chain + 两条链规则压进单个 `nft-init`（6 条语句、独立 `;` 分句，符合内核 nft 语句级形状表），元素增删按集合各一条动作
- fix(iplist): nft 动作幂等性——`nft add` 对已存在对象返回非零，改为「先 `nft-list` 探活、缺失才 `nft-init`」，进程内缓存结果；表被重建时按 `iplist.json` 回灌规则（过期封禁跳过），删除元素失败且属宿主侧缺失时只清 kore 记录并如实回 `applied=false + note`
- fix(iplist): IPv6 明确返回 `E_UNSUPPORTED` + 可操作提示（改走 ufw），不再有「声明了 allow6/deny6 却无对应 root 动作」的半成品状态
- feat(iplist): 防爆破阈值可配（默认登录失败 5 次封禁 10 分钟，1–1000 次 / 1–1440 分钟）；`recordFail` 达阈值自动下发带 timeout 的临时封禁，nft 集合元素自动过期，插件零 ticker；失败计数 10 分钟窗口、封禁后清零
- feat(root-action): 新增 6 条形状锁定 nft root_actions（kore 自有表 kore_fw + allow4/deny4 集合 + input base chain + 元素增删）；root 动作经 ADR-0018 内核代理，插件不提权、不碰宿主防火墙真实规则
- feat(degrade): 非 root 且无内核 root-action 通道时 IP 写操作 fail-closed 返回 `E_NEED_ROOT` + 可操作 hint（与 status/rules 口径一致），dry-run 不触碰通道
- feat(state): 规则与防爆破配置落 `<KORE_STATE_DIR>/iplist.json`（0600 原子写，与 config.json 同口径）；不引入新依赖，只用标准库 + pluginapi
- docs: README 方法表 / 安全护栏同步；`info.json` method_capabilities 全量声明（15 条）
- test: iplist 写入/回读/删除、防爆破达阈值自动封禁、参数白名单、CIDR 归一化、IPv6 拒收、探活后不重复初始化、dry-run 零通道、无通道降级；root_actions 的 SDK schema + 追加参数形状 + 「≤16 条」协议上限守护；go test / -race 全绿

## 0.2.7 (2026-11-24)

- feat(config): 补齐 `firewall.config.get` / `firewall.config.set` 契约（PLUGIN-CONFIG §1/§2），统一配置面板出现 firewall 设置页；dispatch 命中 `<id>.config.*` 与裸 `config.*` 两种写法
- feat(config): schema 定义三个真实能力字段——`default_backend`（auto/ufw/iptables）、`ssh_ports`（list int，始终含 22）、`dry_run_default`（bool）；不臆造 fwop 未实现的「默认入站策略」（仅只读观测）
- feat(config): 优先级 `config.json > 环境变量 > 代码默认值`，`<KORE_STATE_DIR>/config.json` 0600 原子写（同目录临时文件 → fsync → rename → fsync 目录），损坏/非法配置启动即失败不静默回退
- feat(config): 保存即热生效——`config.set` 校验 → 原子写 → 更新内存 → 注入执行面，下一次方法调用即用新值、PID 不变、`restart_required=false`；注入失败如实返回 `restart_required=true` + warning，不谎报 applied。kore.reload 改为真重载并返回配置摘要
- feat(config): 新增 `internal/plugincfg`（schema/存储/sensitive 掩码/响应形状）与 `fwop.Settings/UpdateSettings`（带锁热更，SSH 护栏与 dry-run 缺省读实时值）；本仓无凭据字段，sensitive 机制保留但不臆造敏感项（G-30）
- feat(protocol): `info.json` 的 `method_capabilities` 补 `firewall.config.get=system:read` / `firewall.config.set=system:admin`；capabilities 期望表同步
- test(config): 契约测试覆盖 schema 合规、三字段往返与热生效（含 PID 不变）、非法值 E_INVALID 不落盘、三种 source 优先级、0600 权限、无敏感键、info 声明；go test / -race 全绿
- build: 依赖与包体变化，按 RELEASE §0 bump patch；dist 两打 sha 一致

## 0.2.6 (2026-11-23)

- build: `pluginapi v0.1.3 → v0.1.4`（v0.1.4 含 ufw enable/disable 受控形状）；**0.2.5 未发 tag/release 已作废**，直接以 0.2.6 发布（require 变化必然改变 dist sha，按 RELEASE §0 必须 bump）

- feat(protocol): 新增 `firewall.enable` / `firewall.disable`（参数 `{dry_run}`，返回与 allow/deny 同形的 `WriteResult`）；**走 ADR-0018 root-action 通道**，新增形状锁定的 `ufw-enable` / `ufw-disable` 两个 root_actions（argv 固定，禁止追加参数）
- feat(protocol): `info.json` 补全量 `method_capabilities`：`firewall.status` / `firewall.rules` → `system:read`；`allowPort` / `denyPort` / `deleteRule` / `enable` / `disable` → `system:admin`
- fix(protocol): 非 root 且通道不可用时 enable/disable 返回 `E_NEED_ROOT` + `detail.hint`（HTTP 403），不回 401
- test: capability 声明一致性（info.json ↔ 业务动词表驱动）、enable/disable 的 dry_run / 幂等 / 非 root 回退
- **边界（历史口径，已被 0.3.0 覆盖）**：当时防爆破归 `kore-plugin-ssh-guard`；0.3.0 起 firewall 自持「失败计数 → 临时封禁」链路，`ssh-guard` 的 fail2ban 独立，勿对同一 IP 配重复策略

## 0.2.4 (2026-11-23)

- build: 依赖升级 `pluginapi v0.1.2 → v0.1.3`（编译期模块版本写入二进制）改变 dist 包体，
  按 RELEASE §0「同 id@version 只允许一个 sha，任何改变 dist sha 的改动必须 bump」升 patch。
  **已发布的 v0.2.3（sha `353d5626…c651b` / 2808093 B）不受影响、tag 不动**；v0.2.4 为
  干净树可复现的新发布点，功能与 0.2.3 一致，仅依赖与包体变化
- chore: `size_bytes` 按新包体重新收敛（`make dist` 回填）

## 0.2.3 (2026-11-23)

- fix(protocol): `firewall.rules` / 写操作遇到 root 权限缺失时返回 `E_NEED_ROOT`（HTTP 403）+ `detail.hint`，不再误报 `E_UNAUTHORIZED`（401 会被前端读成"登录失效"）
- test: 权限错误断言从 `E_UNAUTHORIZED` 改为 `E_NEED_ROOT`，并校验 `detail.hint` 含 kored 提权提示
- docs: README / 前端提权指引与 ADR-0018 统一口径

## 0.2.2 (2026-11-23)

- feat(protocol): `info.json` 声明 `requires_root: true` 与 5 个 `root_actions`（ufw-status / ufw-allow / ufw-deny / ufw-delete / iptables-s），argv 固定、写动作标 `irreversible`（ADR-0018）
- feat(status): 非 root 且内核注入 `KORE_KERNEL_SOCK` 时经内核 root-action 通道读取 `ufw-status` / `iptables-s`；通道不可用则 `available=false` + `error_code=E_NEED_ROOT` + 可操作 `hint`，不再只有一行英文原文
- feat: 插件侧 root-action 客户端（UDS HTTP + `KORE_PLUGIN_TOKEN` bearer），插件自身仍不谈 root、不 exec sudo/setuid
- test: 通道成功/不可用两条 status 路径；原有直连与降级用例保持通过

## 0.2.1 (2026-11-23)

- build: 位级可复现打包（stage chmod + tar --mode 归一、size_bytes 收敛），二进制改嵌 manifest.json，消除同版本 sha 漂移

## 0.2.0 (2026-11-23)

- feat: firewall 从 L0 骨架升级为真实执行面——`firewall.status` 探测 ufw / iptables 后端并回读状态、默认入站策略与规则数
- feat: `firewall.rules` 真实解析 `ufw status numbered`（保留编号）与 `iptables -S` 的 INPUT 链，输出统一规则结构
- feat: 新增 `firewall.denyPort` 与 `firewall.deleteRule`；`firewall.allowPort` / `denyPort` 以固定 argv 调用 ufw，支持 `from` 来源限定与 `comment`
- feat: SSH 保护——deny 22 / `KORE_SSH_PORT` 一律拒绝；删除入站 SSH 放行规则拒绝；写操作要求 `system:admin`
- feat: 写操作支持 `dry_run=true`，只返回将要执行的命令，不执行
- feat: 命令执行统一 `LC_ALL=C`、10s 超时、无 shell，失败按权限/上游分类
- test: 参数白名单、SSH 护栏、dry-run 不执行、ufw/iptables fixture 解析、capability 门禁
- test: 四类故障注入改为经真实 `Runtime` 执行面注入，覆盖四个业务方法
- test: 真实 E2E（只读 + dry-run）验证 status/rules 真实输出、前后系统 diff 为空、deny 22 被拒
- docs: README 重写为真实后端口径，明确「启用/禁用不在方法面」与真机未执行写操作的证据边界
- build: `dist` 增加 size_bytes 2-cycle 检测（gzip 长度对数字内容敏感时 ±1 字节往返），保证包内清单与源清单一致、重复构建与任意起点重建 sha 相同

## 0.1.0 (2026-11-22)

- feat: 新建 firewall 插件骨架，复用 kore.plugin.v1 握手与会话循环
- feat: firewall.rules / firewall.allowPort 方法级参数校验与结构化结果，端口限制 1-65535、协议限 tcp/udp/icmp，返回 applied=false，不真调 iptables/nftables/firewalld
- feat: 四类故障注入测试（kill -9 / 超时 / 磁盘满 / cgroup 超限），验证方法级错误返回
- build: 确定性打包（--sort=name --mtime=@0 --owner=0 --numeric-owner + gzip -9n），size_bytes 不动点回写源清单
