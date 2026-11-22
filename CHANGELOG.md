# Changelog

## 0.1.0 (2026-11-22)

- feat: 新建 firewall 插件骨架，复用 kore.plugin.v1 握手与会话循环
- feat: firewall.rules / firewall.allowPort 方法级参数校验与结构化结果，端口限制 1-65535、协议限 tcp/udp/icmp，返回 applied=false，不真调 iptables/nftables/firewalld
- feat: 四类故障注入测试（kill -9 / 超时 / 磁盘满 / cgroup 超限），验证方法级错误返回
- build: 确定性打包（--sort=name --mtime=@0 --owner=0 --numeric-owner + gzip -9n），size_bytes 不动点回写源清单
