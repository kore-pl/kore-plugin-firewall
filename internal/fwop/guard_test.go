package fwop

import "testing"

// testPolicyRuntime 构造带指定 SSH 保护端口的执行面（始终并入 22）。
func testPolicyRuntime(t *testing.T, sshPorts ...int) *Runtime {
	t.Helper()
	runtime, err := New(Options{
		Capabilities: []string{CapabilityAdmin},
		SSHPorts:     sshPorts,
		Runner:       &fakeRunner{},
		Resolve:      stubResolver(BackendUFW),
	})
	if err != nil {
		t.Fatalf("构造执行面失败: %v", err)
	}
	return runtime
}

// TestDenySSHPortGuard deny 22 / KORE_SSH_PORT 必须被拒，且错误文案明确。
func TestDenySSHPortGuard(t *testing.T) {
	def := testPolicyRuntime(t)
	perr := def.checkDenySSHPort(22)
	if perr == nil || perr.Code != "E_UNAUTHORIZED" {
		t.Fatalf("deny 22 应返回 E_UNAUTHORIZED，实际: %+v", perr)
	}
	want := "拒绝屏蔽 SSH 端口 22：这会导致你无法再连接到服务器。如确实需要，请先确认有其他登录方式"
	if perr.Message != want {
		t.Fatalf("SSH 保护文案不符:\n实际=%q\n期望=%q", perr.Message, want)
	}
	if perr := def.checkDenySSHPort(2222); perr != nil {
		t.Fatalf("未配置 2222 时不应拦截: %v", perr)
	}

	custom := testPolicyRuntime(t, 2222)
	if perr := custom.checkDenySSHPort(22); perr == nil || perr.Message != want {
		t.Fatalf("配置了自定义端口后 22 仍须受保护: %+v", perr)
	}
	if perr := custom.checkDenySSHPort(2222); perr == nil || perr.Code != "E_UNAUTHORIZED" {
		t.Fatalf("deny 2222 应被拒，实际: %+v", perr)
	}
	if perr := custom.checkDenySSHPort(8080); perr != nil {
		t.Fatalf("deny 8080 不应被 SSH 保护拦截: %v", perr)
	}
}

// TestDeleteSSHAllowGuard 只拦截「入站 + allow + 覆盖 SSH 端口」的删除。
func TestDeleteSSHAllowGuard(t *testing.T) {
	runtime := testPolicyRuntime(t)
	blocked := []Rule{
		{Index: 1, Action: ActionAllow, Direction: DirectionIn, Proto: ProtoTCP, Port: "22"},
		{Index: 2, Action: ActionAllow, Direction: DirectionIn, Proto: ProtoAny, Port: ""},
		{Index: 3, Action: ActionAllow, Direction: DirectionIn, Proto: ProtoTCP, Port: "20:30"},
		{Index: 4, Action: ActionAllow, Direction: DirectionIn, Proto: ProtoTCP, Port: "80,22,443"},
		{Index: 5, Action: ActionAllow, Direction: DirectionIn, Proto: ProtoUDP, Port: "22"},
	}
	for _, rule := range blocked {
		if perr := runtime.checkDeleteSSHAllow(rule); perr == nil || perr.Code != "E_UNAUTHORIZED" {
			t.Fatalf("规则 %+v 应被 SSH 保护拦截，实际: %+v", rule, perr)
		}
	}
	allowed := []Rule{
		{Index: 6, Action: ActionAllow, Direction: DirectionIn, Proto: ProtoTCP, Port: "80"},
		{Index: 7, Action: ActionDeny, Direction: DirectionIn, Proto: ProtoTCP, Port: "22"},
		{Index: 8, Action: ActionAllow, Direction: DirectionOut, Proto: ProtoTCP, Port: "22"},
		{Index: 9, Action: ActionReject, Direction: DirectionIn, Proto: ProtoTCP, Port: "22"},
	}
	for _, rule := range allowed {
		if perr := runtime.checkDeleteSSHAllow(rule); perr != nil {
			t.Fatalf("规则 %+v 不应被拦截，实际: %v", rule, perr)
		}
	}

	custom := testPolicyRuntime(t, 2222)
	if perr := custom.checkDeleteSSHAllow(Rule{Index: 10, Action: ActionAllow, Direction: DirectionIn, Proto: ProtoTCP, Port: "2222"}); perr == nil {
		t.Fatal("配置的 KORE_SSH_PORT=2222 放行规则应被拦截")
	}
}
