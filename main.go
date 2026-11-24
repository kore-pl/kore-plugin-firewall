// Package main 是 kore 的 firewall 插件：防火墙状态/规则读取与端口放行/拒绝管理。
//
// 真实执行面：优先探测 ufw（/usr/sbin/ufw），回退 iptables（只读）；写操作仅支持 ufw，
// 且统一经过 SSH 保护、参数白名单与 dry-run。插件不启用/禁用防火墙、不改宿主配置文件，
// 只调用固定 argv 的外部命令（不经过 shell）。
//
// 协议面（kore.plugin.v1）：UDS → kore.hello 握手 → 会话循环读 request、
// 按 method 分发并回 response；stdout 留给协议，日志一律写 stderr。
package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/pengtang1024/kore-plugin-firewall/internal/fwop"
)

// main 按退出码区分失败：0 优雅退出、1 启动或协议失败。
func main() {
	logger := newLogger(os.Getenv("KORE_LOG_LEVEL"))
	if err := run(logger); err != nil {
		logger.Error("插件退出", "err", err)
		os.Exit(1)
	}
}

// run 依次完成配置加载、执行面构造、建连、hello 握手与会话循环；
// 收到 kore.shutdown 后返回 nil。
func run(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	// SSH 保护端口用已按 config.json > env > default 解析好的值，
	// 避免环境变量在文件配置存在时二次解析打架（PLUGIN-CONFIG §4）。
	sshPorts := append([]int(nil), cfg.values.SSHPorts...)
	rootAction := rootActionFunc()
	runtime, err := fwop.New(fwop.Options{
		Capabilities: cfg.capabilities, SSHPorts: sshPorts, RootAction: rootAction,
	})
	if err != nil {
		return err
	}
	// 配置契约优先于 KORE_SSH_PORT 等环境变量（PLUGIN-CONFIG §4）；
	// 启动失败要写明原因，不静默回退到环境变量默认值。
	if err := cfg.applySettings(runtime); err != nil {
		return fmt.Errorf("应用插件配置失败: %w", err)
	}
	conn, err := net.Dial("unix", cfg.socket)
	if err != nil {
		return fmt.Errorf("连接主壳 socket %s: %w", cfg.socket, err)
	}
	defer func() { _ = conn.Close() }()
	if err := handshake(conn, cfg); err != nil {
		return err
	}
	logger.Info("hello 完成", "plugin_id", cfg.id, "version", cfg.version,
		"ssh_ports", runtime.SSHPorts(), "root_action_channel", rootAction != nil)
	return serve(conn, cfg, runtime, logger)
}
