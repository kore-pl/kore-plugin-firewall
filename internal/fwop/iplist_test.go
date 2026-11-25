package fwop

import (
	"encoding/json"
	"github.com/pengtang1024/kore/pkg/pluginapi"
	"testing"
	"time"
)

func iplistTestRuntime(t *testing.T, actions *[]string) *Runtime {
	t.Helper()
	dir := t.TempDir()
	rt, err := New(Options{
		Capabilities: []string{CapabilityAdmin}, SSHPorts: []int{DefaultSSHPort},
		Runner: &fakeRunner{}, Resolve: stubResolver(BackendUFW), StateDir: dir,
		RootAction: func(id string, args []string) ([]byte, int, error) {
			*actions = append(*actions, id)
			return nil, 0, nil
		},
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	return rt
}

func TestIPListWriteAndBruteForce(t *testing.T) {
	var actions []string
	rt := iplistTestRuntime(t, &actions)
	for _, tc := range []struct{ method, ip string }{
		{"firewall.ipAllow", "203.0.113.7"},
		{"firewall.ipDeny", "10.0.0.0/8"},
	} {
		params := "{\"ip\":\"" + tc.ip + "\",\"comment\":\"kore test\"}"
		raw, perr := rt.Call(tc.method, json.RawMessage(params))
		if perr != nil {
			t.Fatalf("%s 意外失败: %+v", tc.method, perr)
		}
		var res IPWriteResult
		if err := json.Unmarshal(raw, &res); err != nil {
			t.Fatal(err)
		}
		if !res.Applied || res.Rule.IP != tc.ip {
			t.Fatalf("%s 结果不符: %+v", tc.method, res)
		}
	}
	if !isRoot() && len(actions) < 2 {
		t.Fatalf("非 root 应经通道下发至少两次，实际 %v", actions)
	}
	bruteParams := "{\"enabled\":true,\"threshold\":2,\"ban_min\":1}"
	if _, perr := rt.Call("firewall.bruteSet", json.RawMessage(bruteParams)); perr != nil {
		t.Fatalf("bruteSet 失败: %+v", perr)
	}
	failParams := "{\"ip\":\"198.51.100.23\"}"
	for i := 0; i < 2; i++ {
		raw, perr := rt.Call("firewall.recordFail", json.RawMessage(failParams))
		if perr != nil {
			t.Fatalf("recordFail 失败: %+v", perr)
		}
		var res IPFailResult
		if err := json.Unmarshal(raw, &res); err != nil {
			t.Fatal(err)
		}
		if i == 0 && res.Banned {
			t.Fatal("第一次失败不应封禁")
		}
		if i == 1 && !res.Banned {
			t.Fatalf("第二次失败应封禁: %+v", res)
		}
	}
	raw, perr := rt.Call("firewall.ipList", nil)
	if perr != nil {
		t.Fatalf("ipList 失败: %+v", perr)
	}
	var list IPListResult
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	if list.Count != 3 || !list.Brute.Enabled || list.Brute.Threshold != 2 || list.Brute.BanMin != 1 {
		t.Fatalf("回读不符: %+v", list)
	}
	for _, rule := range list.Rules {
		if rule.Mode == IPModeBan && rule.ExpiresAt != "" {
			if exp, err := time.Parse(time.RFC3339, rule.ExpiresAt); err != nil || !exp.After(time.Now()) {
				t.Fatalf("ban 过期时间不合法: %s %v", rule.ExpiresAt, err)
			}
		}
	}
	removeParams := "{\"id\":\"" + list.Rules[0].ID + "\"}"
	_, perr = rt.Call("firewall.ipRemove", json.RawMessage(removeParams))
	if perr != nil {
		t.Fatalf("ipRemove 失败: %+v", perr)
	}
	raw, _ = rt.Call("firewall.ipList", nil)
	var after IPListResult
	_ = json.Unmarshal(raw, &after)
	if after.Count != 2 {
		t.Fatalf("删除后应剩 2 条，实际 %d", after.Count)
	}
}

func TestIPListValidationAndDryRun(t *testing.T) {
	var actions []string
	rt := iplistTestRuntime(t, &actions)
	for _, params := range []string{
		"{\"mode\":\"allow\",\"ip\":\"example.com\"}",
		"{\"mode\":\"allow\",\"ip\":\"1.2.3.4;rm\"}",
		"{\"mode\":\"bogus\",\"ip\":\"1.2.3.4\"}",
		"{\"mode\":\"allow\",\"ip\":\"0.0.0.0/33\"}",
		"{\"mode\":\"allow\",\"ip\":\"\"}",
	} {
		_, perr := rt.Call("firewall.ipAllow", json.RawMessage(params))
		if perr == nil || perr.Code != pluginapi.E_INVALID {
			t.Fatalf("%s 应 E_INVALID，实际 %+v", params, perr)
		}
	}
	if len(actions) != 0 {
		t.Fatalf("非法参数不应下发通道: %v", actions)
	}
	dryParams := "{\"mode\":\"allow\",\"ip\":\"203.0.113.7\",\"dry_run\":true}"
	raw, perr := rt.Call("firewall.ipAllow", json.RawMessage(dryParams))
	if perr != nil {
		t.Fatalf("dry-run 失败: %+v", perr)
	}
	var res IPWriteResult
	_ = json.Unmarshal(raw, &res)
	if res.Applied || !res.DryRun || len(res.Command) == 0 {
		t.Fatalf("dry-run 结果不符: %+v", res)
	}
	if len(actions) != 0 {
		t.Fatalf("dry-run 不应下发通道: %v", actions)
	}
}

// TestIPListRejectsIPv6 IPv6 名单不在本期范围（root_actions 上限 16 条）：
// 必须给 E_UNSUPPORTED + 可操作提示，绝不能静默当成 IPv4 规则塞进 allow4。
func TestIPListRejectsIPv6(t *testing.T) {
	var actions []string
	rt := iplistTestRuntime(t, &actions)
	for _, ip := range []string{"2001:db8::1", "2001:db8::/32"} {
		params := "{\"ip\":\"" + ip + "\"}"
		_, perr := rt.Call("firewall.ipAllow", json.RawMessage(params))
		if perr == nil || perr.Code != pluginapi.E_UNSUPPORTED {
			t.Fatalf("%s 应 E_UNSUPPORTED，实际 %+v", ip, perr)
		}
		if len(perr.Message) < 8 {
			t.Fatalf("%s 的 E_UNSUPPORTED 必须带可操作说明: %+v", ip, perr)
		}
	}
	if len(actions) != 0 {
		t.Fatalf("IPv6 被拒时不应下发通道: %v", actions)
	}
}

// TestIPListCIDRNormalized 网段归一化：状态里存的值必须是内核实际生效的值。
func TestIPListCIDRNormalized(t *testing.T) {
	var actions []string
	rt := iplistTestRuntime(t, &actions)
	raw, perr := rt.Call("firewall.ipAllow", json.RawMessage("{\"ip\":\"10.1.2.3/8\"}"))
	if perr != nil {
		t.Fatalf("ipAllow 失败: %+v", perr)
	}
	var res IPWriteResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	if res.Rule.IP != "10.0.0.0/8" {
		t.Fatalf("网段应归一化为 10.0.0.0/8，实际 %q", res.Rule.IP)
	}
}

// TestIPListInitOnlyOnce 探活成功后不再重复初始化（nft add 不幂等，重复下发会失败）。
func TestIPListInitOnlyOnce(t *testing.T) {
	var actions []string
	rt := iplistTestRuntime(t, &actions)
	for i := 0; i < 3; i++ {
		if _, perr := rt.Call("firewall.ipAllow", json.RawMessage("{\"ip\":\"203.0.113.7\"}")); perr != nil {
			t.Fatalf("第 %d 次 ipAllow 失败: %+v", i, perr)
		}
	}
	inits := 0
	for _, id := range actions {
		if id == "nft-init" {
			inits++
		}
	}
	if inits != 0 {
		t.Fatalf("探活已成功时不应初始化，实际 init %d 次（动作序列 %v）", inits, actions)
	}
}

func TestIPListNoChannelDegrades(t *testing.T) {
	if isRoot() {
		t.Skip("root 下本来就可执行，跳过降级用例")
	}
	dir := t.TempDir()
	rt, err := New(Options{
		Capabilities: []string{CapabilityAdmin}, SSHPorts: []int{DefaultSSHPort},
		Runner: &fakeRunner{}, Resolve: stubResolver(BackendUFW), StateDir: dir,
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	allowParams := "{\"mode\":\"allow\",\"ip\":\"203.0.113.7\"}"
	_, perr := rt.Call("firewall.ipAllow", json.RawMessage(allowParams))
	if perr == nil || perr.Code != CodeNeedRoot {
		t.Fatalf("应 E_NEED_ROOT，实际 %+v", perr)
	}
	var detail struct {
		Hint string `json:"hint"`
	}
	if err := json.Unmarshal(perr.Detail, &detail); err != nil || len(detail.Hint) < 8 {
		t.Fatalf("E_NEED_ROOT 必须带可操作 hint: detail=%s", perr.Detail)
	}
}
