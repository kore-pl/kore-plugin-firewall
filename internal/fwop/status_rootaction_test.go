package fwop

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// ufwVerboseFixture 是 `ufw status verbose` 的最小可解析输出。
const ufwVerboseFixture = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
`

// TestStatusViaRootAction 非 root 且注入通道时，status 经 ufw-status 动作读取。
func TestStatusViaRootAction(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("以 root 运行时直接走本地命令，不经通道")
	}
	direct := &fakeRunner{handler: func([]string) (string, string, error) {
		return "", "ERROR: You need to be root to run this script", errors.New("exit 1")
	}}
	channelCalls := make([]string, 0, 1)
	runtime, err := New(Options{
		Capabilities: []string{CapabilityAdmin}, SSHPorts: []int{DefaultSSHPort},
		Runner: direct, Resolve: stubResolver(BackendUFW),
		RootAction: func(actionID string, args []string) ([]byte, int, error) {
			channelCalls = append(channelCalls, actionID)
			return []byte(ufwVerboseFixture), 0, nil
		},
	})
	if err != nil {
		t.Fatalf("构造执行面失败: %v", err)
	}
	status, perr := runtime.Status()
	if perr != nil {
		t.Fatalf("Status 不应返回协议错误: %v", perr)
	}
	if len(channelCalls) != 1 || channelCalls[0] != "ufw-status" {
		t.Fatalf("应经 root-action 执行 ufw-status，实际 %v", channelCalls)
	}
	if len(direct.calls) != 0 {
		t.Fatalf("走通道时不应直连命令，实际 %v", direct.commandStrings())
	}
	if !status.Available || !status.Enabled || status.ErrorCode != "" {
		t.Fatalf("通道成功应 available=true/enabled=true，实际 %+v", status)
	}
}

// TestStatusRootActionUnavailable 通道失败时显式降级：available=false + E_NEED_ROOT + hint。
func TestStatusRootActionUnavailable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("以 root 运行时不经通道")
	}
	runtime, err := New(Options{
		Capabilities: []string{CapabilityAdmin}, SSHPorts: []int{DefaultSSHPort},
		Runner: &fakeRunner{}, Resolve: stubResolver(BackendUFW),
		RootAction: func(string, []string) ([]byte, int, error) {
			return nil, -1, errors.New("dial unix /run/kore/kore.sock: permission denied")
		},
	})
	if err != nil {
		t.Fatalf("构造执行面失败: %v", err)
	}
	status, perr := runtime.Status()
	if perr != nil {
		t.Fatalf("降级不应返回协议错误: %v", perr)
	}
	if status.Available || status.ErrorCode != "E_NEED_ROOT" {
		t.Fatalf("应 available=false + E_NEED_ROOT，实际 %+v", status)
	}
	if !strings.Contains(status.Hint, "kored") || !strings.Contains(status.Error, "E_NEED_ROOT") {
		t.Fatalf("error/hint 应可操作，实际 %+v", status)
	}
}
