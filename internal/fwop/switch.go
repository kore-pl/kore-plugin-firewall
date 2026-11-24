package fwop

// 本文件实现 firewall.enable / firewall.disable：ufw 的全局开关。
//
// 边界：只做 ufw 启停（iptables 无全局开关，返回 E_UNSUPPORTED）；不改默认策略、
// 不改规则、不做防爆破（fail2ban/sshguard 归 kore-plugin-ssh-guard）。
//
// ADR-0018：非 root 且内核注入了 root-action 通道时，经 `ufw-enable` / `ufw-disable`
// 两个形状锁定的动作以 uid=0 执行；通道不可用时返回 E_NEED_ROOT + hint，
// 不退化成 E_UNAUTHORIZED（401 会被前端读成"登录失效"）。

import (
	"fmt"
)

// switchParams 是 firewall.enable / firewall.disable 的入参（对外 schema 显式定形）。
type switchParams struct {
	// DryRun 非 nil 时覆盖配置里的 dry_run 默认值；true 表示只返回命令不执行。
	DryRun *bool `json:"dry_run,omitempty"`
}

// Enable 启用 ufw（firewall.enable）。
func (r *Runtime) Enable(dryRun bool) (WriteResult, error) {
	return r.switchFirewall("enable", "ufw-enable", dryRun)
}

// Disable 停用 ufw（firewall.disable）。
func (r *Runtime) Disable(dryRun bool) (WriteResult, error) {
	return r.switchFirewall("disable", "ufw-disable", dryRun)
}

// switchFirewall 是 enable/disable 的共同执行序：ufw 后端 → dry-run → root/通道。
// ufw 的 enable/disable 天然幂等（已启用再 enable 仍退出 0），这里不额外维护状态。
func (r *Runtime) switchFirewall(sub, actionID string, dryRun bool) (WriteResult, error) {
	path, ok := r.resolve(BackendUFW)
	if !ok {
		return WriteResult{}, opErr(ErrKindUnsupported, "开关仅支持 ufw 后端：未检测到 ufw")
	}
	argv := []string{path, sub}
	result := WriteResult{DryRun: dryRun, Backend: BackendUFW, Command: argv}
	if dryRun {
		return result, nil
	}
	if isRoot() {
		if _, err := r.run(argv); err != nil {
			return WriteResult{}, err
		}
		result.Applied = true
		return result, nil
	}
	if r.rootAction == nil {
		return WriteResult{}, opErr(ErrKindPermission,
			"非 root 且内核 root-action 通道不可用，无法执行 ufw %s", sub)
	}
	if _, exitCode, err := r.rootAction(actionID, nil); err != nil {
		return WriteResult{}, opErr(ErrKindUpstream, "root-action %s 调用失败：%v", actionID, err)
	} else if exitCode != 0 {
		return WriteResult{}, opErr(ErrKindUpstream, "root-action %s 退出码 %d", actionID, exitCode)
	}
	result.Applied = true
	return result, nil
}

// describeSwitch 供错误/日志复用（避免 fmt 未使用）。
func describeSwitch(actionID string) string { return fmt.Sprintf("root-action %s", actionID) }
