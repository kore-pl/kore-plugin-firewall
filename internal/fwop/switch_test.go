package fwop

import (
	"encoding/json"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// newSwitchRuntime 构造只解析 ufw 的执行面；rootAction 为 nil 表示通道不可用。
// 测试进程以非 root 运行，因此 isRoot()=false，覆盖的是 ADR-0018 通道回退路径。
func newSwitchRuntime(t *testing.T, rootAction RootActionFunc) *Runtime {
	t.Helper()
	return &Runtime{
		runner:     &fakeRunner{},
		resolve:    stubResolver(BackendUFW),
		rootAction: rootAction,
		policy:     Policy{Capabilities: []string{CapabilityAdmin}, SSHPorts: []int{DefaultSSHPort}},
	}
}

func decodeWrite(t *testing.T, raw json.RawMessage) WriteResult {
	t.Helper()
	var out WriteResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("结果不是 WriteResult: %v（%s）", err, raw)
	}
	return out
}

// TestSwitchDryRun 证明 dry_run 只返回命令、不执行也不走通道。
func TestSwitchDryRun(t *testing.T) {
	called := 0
	rt := newSwitchRuntime(t, func(string, []string) ([]byte, int, error) { called++; return nil, 0, nil })
	out, perr := rt.Call("firewall.enable", json.RawMessage(`{"dry_run":true}`))
	if perr != nil {
		t.Fatalf("dry_run 不应报错: %+v", perr)
	}
	result := decodeWrite(t, out)
	if result.Applied || !result.DryRun || result.Backend != BackendUFW {
		t.Fatalf("dry_run 结果不符: %+v", result)
	}
	if len(result.Command) != 2 || result.Command[1] != "enable" {
		t.Fatalf("dry_run 命令不符: %v", result.Command)
	}
	if called != 0 || len(rt.runner.(*fakeRunner).calls) != 0 {
		t.Fatalf("dry_run 不得执行（channel=%d runner=%d）", called, len(rt.runner.(*fakeRunner).calls))
	}
}

// TestSwitchViaRootAction 证明非 root 时 enable/disable 经内核通道固定 action id 执行。
func TestSwitchViaRootAction(t *testing.T) {
	var ids []string
	rt := newSwitchRuntime(t, func(id string, args []string) ([]byte, int, error) {
		if len(args) != 0 {
			t.Fatalf("enable/disable 不允许追加参数: %v", args)
		}
		ids = append(ids, id)
		return []byte("Firewall is active and enabled on system startup\n"), 0, nil
	})
	for i, verb := range []string{"enable", "disable", "enable"} {
		out, perr := rt.Call("firewall."+verb, json.RawMessage(`{}`))
		if perr != nil {
			t.Fatalf("%s 失败: %+v", verb, perr)
		}
		if !decodeWrite(t, out).Applied {
			t.Fatalf("%s 应 applied", verb)
		}
		_ = i
	}
	want := []string{"ufw-enable", "ufw-disable", "ufw-enable"}
	if len(ids) != len(want) {
		t.Fatalf("通道调用次数不符: %v", ids)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("action id 不符: got %v want %v", ids, want)
		}
	}
	if len(rt.runner.(*fakeRunner).calls) != 0 {
		t.Fatalf("非 root 不得直接跑命令: %v", rt.runner.(*fakeRunner).commandStrings())
	}
}

// TestSwitchNoChannelNeedsRoot 证明通道不可用时返回 E_NEED_ROOT + hint（不是 401）。
func TestSwitchNoChannelNeedsRoot(t *testing.T) {
	rt := newSwitchRuntime(t, nil)
	_, perr := rt.Call("firewall.disable", json.RawMessage(`{}`))
	if perr == nil || perr.Code != CodeNeedRoot {
		t.Fatalf("应返回 E_NEED_ROOT，实际 %+v", perr)
	}
	var detail struct {
		Hint string `json:"hint"`
	}
	if err := json.Unmarshal(perr.Detail, &detail); err != nil || detail.Hint == "" {
		t.Fatalf("E_NEED_ROOT 必须带 detail.hint: %v / %s", err, perr.Detail)
	}
	if perr.Code == pluginapi.E_UNAUTHORIZED {
		t.Fatalf("不得退化成 401")
	}
}
