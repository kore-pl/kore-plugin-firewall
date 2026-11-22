//go:build linux

package e2e

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore-plugin-firewall/internal/fwop"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestFirewallReadOnlyE2E 真实插件进程的只读端到端验证：
// status / rules 真实执行 → dry-run 前后系统视图 diff 为空 → deny 22 被拒 → 优雅退出。
// 硬约束：本测试不执行任何写操作，绝不启用 ufw 或修改规则。
func TestFirewallReadOnlyE2E(t *testing.T) {
	before := captureSnapshot()

	binary := buildPlugin(t)
	socket := filepath.Join(t.TempDir(), "firewall.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("监听 UDS 失败: %v", err)
	}
	defer func() { _ = listener.Close() }()
	_ = listener.(*net.UnixListener).SetDeadline(time.Now().Add(120 * time.Second))

	process, stderr := startPlugin(t, binary, socket)
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("接受插件连接失败: %v（stderr=%s）", err, stderr.String())
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))
	handshake(t, conn)

	ufwPath := probeBinary("ufw")
	iptablesPath := probeBinary("iptables")

	// 1) status：真实探测后端；非 root 时 available=false 且 error 说明原因。
	status := decode[fwop.StatusResult](t, mustCall(t, conn, "e2e-status", "firewall.status", nil))
	if status.Backend != fwop.BackendUFW && status.Backend != fwop.BackendIptables && status.Backend != fwop.BackendNone {
		t.Fatalf("未知 backend: %q", status.Backend)
	}
	if ufwPath != "" && status.Backend != fwop.BackendUFW {
		t.Fatalf("ufw 存在但 status backend=%q", status.Backend)
	}
	if !status.Available && status.Error == "" {
		t.Fatalf("available=false 时必须有 error：%+v", status)
	}
	t.Logf("E2E_STATUS backend=%s available=%v enabled=%v default_in=%q rules_count=%d error=%q",
		status.Backend, status.Available, status.Enabled, status.DefaultIn, status.RulesCount, status.Error)

	// 2) rules：可读时校验结构一致性；非 root 时必须是 E_NEED_ROOT（403 语义，不是 401）。
	rulesResp := request(t, conn, "e2e-rules", "firewall.rules", map[string]any{"backend": "ufw"})
	if rulesResp.Error != nil {
		if rulesResp.Error.Code != fwop.CodeNeedRoot {
			t.Fatalf("rules 失败码=%s，期望 E_NEED_ROOT（message=%q）", rulesResp.Error.Code, rulesResp.Error.Message)
		}
		if status.Available {
			t.Fatalf("status 可读但 rules 被拒，行为不一致：%+v", rulesResp.Error)
		}
		t.Logf("E2E_RULES_DENIED code=%s message=%q", rulesResp.Error.Code, rulesResp.Error.Message)
	} else {
		rules := decode[fwop.RulesResult](t, rulesResp.Result)
		if rules.Count != len(rules.Rules) || rules.Backend != fwop.BackendUFW {
			t.Fatalf("rules 结果不一致: backend=%s count=%d len=%d", rules.Backend, rules.Count, len(rules.Rules))
		}
		t.Logf("E2E_RULES backend=%s count=%d first=%+v", rules.Backend, rules.Count, firstRule(rules.Rules))
	}

	// 3) dry-run：返回命令但不执行；随后用系统快照证明未改动。
	dryRun := decode[fwop.WriteResult](t, mustCall(t, conn, "e2e-dry-allow", "firewall.allowPort", map[string]any{
		"port": 18080, "proto": "tcp", "comment": "kore-e2e-dryrun", "dry_run": true,
	}))
	if dryRun.Applied || !dryRun.DryRun || dryRun.Backend != fwop.BackendUFW {
		t.Fatalf("dry-run 结果不符: %+v", dryRun)
	}
	command := strings.Join(dryRun.Command, " ")
	if !strings.Contains(command, "18080") || !strings.Contains(command, "proto tcp") {
		t.Fatalf("dry-run 命令不符: %q", command)
	}
	t.Logf("E2E_DRYRUN_COMMAND %s", command)

	// 4) deny 22：普通与 dry-run 都必须被拒，且不执行任何命令。
	wantSSHMessage := "拒绝屏蔽 SSH 端口 22：这会导致你无法再连接到服务器。如确实需要，请先确认有其他登录方式"
	for _, params := range []map[string]any{
		{"port": 22},
		{"port": 22, "proto": "udp", "dry_run": true},
	} {
		resp := request(t, conn, "e2e-deny-ssh", "firewall.denyPort", params)
		if resp.Error == nil || resp.Error.Code != pluginapi.E_UNAUTHORIZED {
			t.Fatalf("deny 22 应返回 E_UNAUTHORIZED，实际: %+v（params=%v）", resp.Error, params)
		}
		if resp.Error.Message != wantSSHMessage {
			t.Fatalf("deny 22 文案不符: %q", resp.Error.Message)
		}
		t.Logf("E2E_DENY_SSH_REJECTED code=%s message=%q", resp.Error.Code, resp.Error.Message)
	}

	// 5) 非法端口：参数白名单在协议层拦截。
	invalid := request(t, conn, "e2e-bad-port", "firewall.allowPort", map[string]any{"port": 70000, "dry_run": true})
	if invalid.Error == nil || invalid.Error.Code != pluginapi.E_INVALID {
		t.Fatalf("port=70000 应返回 E_INVALID，实际: %+v", invalid.Error)
	}
	t.Logf("E2E_INVALID_PORT code=%s message=%q", invalid.Error.Code, invalid.Error.Message)

	// 6) 前后快照 diff：dry-run 与护栏拒绝不得改变系统防火墙视图。
	after := captureSnapshot()
	if before != after {
		t.Fatalf("dry-run/护栏期间系统防火墙视图变化:\nbefore=%+v\nafter=%+v", before, after)
	}
	t.Logf("E2E_DRYRUN_NO_CHANGE ufw=%q iptables=%q user_rules=%+v user6=%+v",
		before.UFWStatus, before.IPTables, before.UserRules, before.User6)

	// 7) 优雅退出。
	if resp := request(t, conn, "e2e-shutdown", "kore.shutdown", nil); resp.Error != nil {
		t.Fatalf("shutdown 响应带错误: %+v", resp.Error)
	}
	waitPlugin(t, process, 10*time.Second)
	if iptablesPath == "" && ufwPath == "" {
		t.Log("E2E_ENV 本机未检测到 ufw / iptables")
	}
}

// decode 把结果原文解码到 T。
func decode[T any](t *testing.T, raw json.RawMessage) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("解码 %s 失败: %v", raw, err)
	}
	return value
}

// firstRule 返回首条规则用于日志（无规则时返回空结构）。
func firstRule(rules []fwop.Rule) fwop.Rule {
	if len(rules) == 0 {
		return fwop.Rule{}
	}
	return rules[0]
}
