# Changelog

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
