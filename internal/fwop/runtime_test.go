package fwop

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// call 是测试用的方法调用入口。
func call(t *testing.T, runtime *Runtime, method, params string) (json.RawMessage, *pluginapi.Error) {
	t.Helper()
	var raw json.RawMessage
	if params != "" {
		raw = json.RawMessage(params)
	}
	return runtime.Call(method, raw)
}

// ufwOnlyRuntime 构造只探测到 ufw 的执行面。
func ufwOnlyRuntime(t *testing.T, runner Runner) *Runtime {
	t.Helper()
	return newTestRuntime(t, runner, BackendUFW)
}

// TestBusinessVerb 方法名归一化：五个方法同时接受 firewall.<verb> 与裸 <verb>。
func TestBusinessVerb(t *testing.T) {
	verbs := []string{"status", "rules", "allowPort", "denyPort", "deleteRule", "enable", "disable"}
	for _, verb := range verbs {
		if got, ok := businessVerb("firewall." + verb); !ok || got != verb {
			t.Fatalf("businessVerb(firewall.%s)=(%q,%v)", verb, got, ok)
		}
		if got, ok := businessVerb(verb); !ok || got != verb {
			t.Fatalf("businessVerb(%s)=(%q,%v)", verb, got, ok)
		}
	}
	for _, method := range []string{"firewall.exec", "firewall.reset", "status2"} {
		if _, ok := businessVerb(method); ok {
			t.Fatalf("%s 不应被接受", method)
		}
	}
}

// TestStatusUFW 真实解析路径：status verbose fixture → 结构化状态。
func TestStatusUFW(t *testing.T) {
	runner := &fakeRunner{handler: func(argv []string) (string, string, error) {
		if strings.Join(argv, " ") != "/usr/sbin/ufw status verbose" {
			t.Fatalf("意外命令: %v", argv)
		}
		return ufwVerboseActive, "", nil
	}}
	result := decodeResult[StatusResult](t, mustCall(t, ufwOnlyRuntime(t, runner), "firewall.status", ""))
	if result.Backend != BackendUFW || !result.Available || !result.Enabled {
		t.Fatalf("状态不符: %+v", result)
	}
	if result.DefaultIn != "deny" || result.RulesCount != 5 || result.Error != "" {
		t.Fatalf("默认策略/规则数/错误不符: %+v", result)
	}
}

// TestStatusPermission 非 root：不返回协议错误，而是 available=false + error 说明。
func TestStatusPermission(t *testing.T) {
	runner := &fakeRunner{handler: func([]string) (string, string, error) { return permissionError() }}
	raw, perr := call(t, ufwOnlyRuntime(t, runner), "firewall.status", "")
	if perr != nil {
		t.Fatalf("status 探测失败不应返回协议错误: %+v", perr)
	}
	result := decodeResult[StatusResult](t, raw, nil)
	if result.Available || result.Backend != BackendUFW {
		t.Fatalf("状态不符: %+v", result)
	}
	if !strings.Contains(result.Error, "You need to be root") {
		t.Fatalf("error 未保留原始 stderr: %q", result.Error)
	}
}

// TestStatusIptablesFallback 无 ufw 时回退 iptables，默认策略从 -P INPUT 解析。
func TestStatusIptablesFallback(t *testing.T) {
	runner := &fakeRunner{handler: func(argv []string) (string, string, error) {
		if strings.Join(argv, " ") != "/usr/sbin/iptables -S" {
			t.Fatalf("意外命令: %v", argv)
		}
		return iptablesSFixture, "", nil
	}}
	runtime := newTestRuntime(t, runner, BackendIptables)
	result := decodeResult[StatusResult](t, mustCall(t, runtime, "status", ""))
	if result.Backend != BackendIptables || !result.Available || !result.Enabled {
		t.Fatalf("状态不符: %+v", result)
	}
	if result.DefaultIn != "deny" || result.RulesCount != 6 {
		t.Fatalf("默认策略/规则数不符: %+v", result)
	}
}

// TestStatusNone 两个后端都不存在时返回 none 与说明，不 panic。
func TestStatusNone(t *testing.T) {
	runtime := newTestRuntime(t, &fakeRunner{})
	result := decodeResult[StatusResult](t, mustCall(t, runtime, "status", "{}"))
	if result.Backend != BackendNone || result.Available || result.Error == "" {
		t.Fatalf("none 状态不符: %+v", result)
	}
}

// TestRulesUFW 编号规则列表：编号、动作、端口形状（数字 vs 字符串）全部正确。
func TestRulesUFW(t *testing.T) {
	runner := &fakeRunner{handler: func(argv []string) (string, string, error) {
		if strings.Join(argv, " ") != "/usr/sbin/ufw status numbered" {
			t.Fatalf("意外命令: %v", argv)
		}
		return ufwNumberedFixture, "", nil
	}}
	raw, perr := call(t, ufwOnlyRuntime(t, runner), "firewall.rules", `{"backend":"ufw"}`)
	result := decodeResult[RulesResult](t, raw, perr)
	if result.Backend != BackendUFW || result.Count != 7 || len(result.Rules) != 7 {
		t.Fatalf("规则列表不符: %+v", result)
	}
	if result.Rules[0].Index != 1 || result.Rules[0].Port != "22" || result.Rules[0].Comment != "ssh" {
		t.Fatalf("首条规则不符: %+v", result.Rules[0])
	}
	text := string(raw)
	if !strings.Contains(text, `"port":22`) {
		t.Fatalf("单端口应输出 JSON 数字: %s", text)
	}
	if !strings.Contains(text, `"port":"80,443"`) || !strings.Contains(text, `"port":"8080:8090"`) {
		t.Fatalf("区间/多端口应输出字符串: %s", text)
	}
}

// TestRulesInactive UFW inactive 时状态编号输出没有规则，应返回空列表而非报错。
func TestRulesInactive(t *testing.T) {
	runner := &fakeRunner{handler: func([]string) (string, string, error) { return "Status: inactive\n", "", nil }}
	result := decodeResult[RulesResult](t, mustCall(t, ufwOnlyRuntime(t, runner), "firewall.rules", "{}"))
	if result.Count != 0 || result.Rules == nil {
		t.Fatalf("inactive 应返回空数组而非 nil: %+v", result)
	}
}

// TestRulesPermission 非 root 读规则返回 E_NEED_ROOT（不是 401）并保留可操作 hint。
func TestRulesPermission(t *testing.T) {
	runner := &fakeRunner{handler: func([]string) (string, string, error) { return permissionError() }}
	_, perr := call(t, ufwOnlyRuntime(t, runner), "firewall.rules", "{}")
	requireCode(t, perr, CodeNeedRoot)
	if !strings.Contains(perr.Message, "You need to be root") {
		t.Fatalf("错误信息未保留 stderr: %q", perr.Message)
	}
	var detail struct {
		Hint string `json:"hint"`
	}
	if err := json.Unmarshal(perr.Detail, &detail); err != nil || !strings.Contains(detail.Hint, "kored") {
		t.Fatalf("E_NEED_ROOT 必须带 detail.hint（含 kored），实际 detail=%s err=%v", perr.Detail, err)
	}
}

// TestRulesBackendSelection backend 参数：未知值 E_INVALID，未安装 E_UNSUPPORTED，自动探测缺失 E_UNSUPPORTED。
func TestRulesBackendSelection(t *testing.T) {
	ufwRuntime := ufwOnlyRuntime(t, &fakeRunner{})
	_, perr := call(t, ufwRuntime, "firewall.rules", `{"backend":"nft"}`)
	requireCode(t, perr, pluginapi.E_INVALID)

	_, perr = call(t, ufwRuntime, "firewall.rules", `{"backend":"iptables"}`)
	requireCode(t, perr, pluginapi.E_UNSUPPORTED)

	_, perr = call(t, newTestRuntime(t, &fakeRunner{}), "firewall.rules", "{}")
	requireCode(t, perr, pluginapi.E_UNSUPPORTED)
}

// TestAllowDryRun dry-run 只返回命令，不产生任何命令调用。
func TestAllowDryRun(t *testing.T) {
	runner := &fakeRunner{}
	runtime := ufwOnlyRuntime(t, runner)
	raw, perr := call(t, runtime, "firewall.allowPort", `{"port":18080,"dry_run":true}`)
	result := decodeResult[WriteResult](t, raw, perr)
	if result.Applied || !result.DryRun || result.Backend != BackendUFW {
		t.Fatalf("dry-run 结果不符: %+v", result)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("dry-run 不应执行任何命令，实际: %v", runner.commandStrings())
	}
	want := []string{"/usr/sbin/ufw", "allow", "proto", "tcp", "from", "any", "to", "any", "port", "18080"}
	if strings.Join(result.Command, " ") != strings.Join(want, " ") {
		t.Fatalf("命令=%v，期望 %v", result.Command, want)
	}
	if result.Rule.Action != ActionAllow || result.Rule.Port != "18080" || result.Rule.From != "any" {
		t.Fatalf("规则回显不符: %+v", result.Rule)
	}
}

// TestAllowApplied 非 dry-run 时执行一次命令，applied=true。
func TestAllowApplied(t *testing.T) {
	runner := &fakeRunner{}
	runtime := ufwOnlyRuntime(t, runner)
	result := decodeResult[WriteResult](t, mustCall(t, runtime, "firewall.allowPort", `{"port":18080,"proto":"tcp"}`))
	if !result.Applied || result.DryRun {
		t.Fatalf("applied 结果不符: %+v", result)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("应执行 1 次命令，实际: %v", runner.commandStrings())
	}
	if !strings.Contains(strings.Join(runner.calls[0], " "), "ufw allow proto tcp from any to any port 18080") {
		t.Fatalf("命令不符: %v", runner.calls[0])
	}
}

// TestAllowFromAndComment from/comment 进入固定 argv 的独立参数项。
func TestAllowFromAndComment(t *testing.T) {
	runner := &fakeRunner{}
	runtime := ufwOnlyRuntime(t, runner)
	raw, perr := call(t, runtime, "firewall.allowPort",
		`{"port":443,"proto":"tcp","from":"10.0.0.0/8","comment":"kore web","dry_run":true}`)
	result := decodeResult[WriteResult](t, raw, perr)
	want := []string{"/usr/sbin/ufw", "allow", "proto", "tcp", "from", "10.0.0.0/8", "to", "any", "port", "443", "comment", "kore web"}
	if strings.Join(result.Command, "|") != strings.Join(want, "|") {
		t.Fatalf("命令=%v，期望 %v", result.Command, want)
	}
	if result.Rule.Comment != "kore web" || result.Rule.From != "10.0.0.0/8" {
		t.Fatalf("规则回显不符: %+v", result.Rule)
	}
}

// TestDenyDryRunAndApplied deny 的命令与执行路径。
func TestDenyDryRunAndApplied(t *testing.T) {
	runner := &fakeRunner{}
	runtime := ufwOnlyRuntime(t, runner)
	result := decodeResult[WriteResult](t, mustCall(t, runtime, "firewall.denyPort", `{"port":8080,"proto":"udp","dry_run":true}`))
	if result.Applied || !result.DryRun || result.Rule.Action != ActionDeny {
		t.Fatalf("deny dry-run 结果不符: %+v", result)
	}
	if !strings.Contains(strings.Join(result.Command, " "), "ufw deny proto udp from any to any port 8080") {
		t.Fatalf("deny 命令不符: %v", result.Command)
	}
	applied := decodeResult[WriteResult](t, mustCall(t, runtime, "firewall.denyPort", `{"port":8080,"proto":"udp"}`))
	if !applied.Applied || len(runner.calls) != 1 {
		t.Fatalf("deny 执行不符: %+v calls=%v", applied, runner.commandStrings())
	}
}

// TestDenySSHRejected 22 与配置端口在 dry-run 下同样被拒，且不执行任何命令。
func TestDenySSHRejected(t *testing.T) {
	runner := &fakeRunner{}
	runtime := ufwOnlyRuntime(t, runner)
	for _, params := range []string{`{"port":22}`, `{"port":22,"dry_run":true}`, `{"port":22,"proto":"udp"}`, `{"port":22,"from":"1.2.3.4"}`} {
		_, perr := call(t, runtime, "firewall.denyPort", params)
		requireCode(t, perr, pluginapi.E_UNAUTHORIZED)
		if perr.Message != "拒绝屏蔽 SSH 端口 22：这会导致你无法再连接到服务器。如确实需要，请先确认有其他登录方式" {
			t.Fatalf("%s 的 SSH 文案不符: %q", params, perr.Message)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("被拒的 deny 不应执行命令: %v", runner.commandStrings())
	}

	custom := newTestRuntime(t, runner, BackendUFW)
	custom.policy.SSHPorts = []int{22, 2222}
	_, perr := call(t, custom, "firewall.denyPort", `{"port":2222,"dry_run":true}`)
	requireCode(t, perr, pluginapi.E_UNAUTHORIZED)
	if !strings.Contains(perr.Message, "2222") {
		t.Fatalf("自定义 SSH 端口文案未含端口: %q", perr.Message)
	}
}

// TestDeleteDryRun 删除前先回读编号规则，dry-run 不执行删除命令。
func TestDeleteDryRun(t *testing.T) {
	runner := &fakeRunner{handler: func(argv []string) (string, string, error) {
		if strings.Join(argv, " ") != "/usr/sbin/ufw status numbered" {
			t.Fatalf("dry-run 只应读取规则，意外命令: %v", argv)
		}
		return ufwNumberedFixture, "", nil
	}}
	runtime := ufwOnlyRuntime(t, runner)
	result := decodeResult[DeleteResult](t, mustCall(t, runtime, "firewall.deleteRule", `{"index":2,"dry_run":true}`))
	if result.Applied || !result.DryRun || result.Deleted.Index != 2 {
		t.Fatalf("delete dry-run 结果不符: %+v", result)
	}
	want := []string{"/usr/sbin/ufw", "--force", "delete", "2"}
	if strings.Join(result.Command, " ") != strings.Join(want, " ") {
		t.Fatalf("删除命令=%v，期望 %v", result.Command, want)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("dry-run 只应调用 1 次（status numbered），实际: %v", runner.commandStrings())
	}
}

// TestDeleteSSHAllowRejected 编号 1 是 SSH 放行规则，删除必须被拒且不执行删除。
func TestDeleteSSHAllowRejected(t *testing.T) {
	runner := &fakeRunner{handler: func([]string) (string, string, error) { return ufwNumberedFixture, "", nil }}
	_, perr := call(t, ufwOnlyRuntime(t, runner), "firewall.deleteRule", `{"index":1}`)
	requireCode(t, perr, pluginapi.E_UNAUTHORIZED)
	if !strings.Contains(perr.Message, "SSH 放行规则") || !strings.Contains(perr.Message, "[1]") {
		t.Fatalf("删除 SSH 规则文案不符: %q", perr.Message)
	}
	for _, command := range runner.commandStrings() {
		if strings.Contains(command, "delete") {
			t.Fatalf("被拒的删除不应执行 delete: %v", runner.commandStrings())
		}
	}
}

// TestDeleteNonSSHRuleAllowed deny / 非 SSH 规则可删除（dry-run 验证命令）。
func TestDeleteNonSSHRuleAllowed(t *testing.T) {
	runner := &fakeRunner{handler: func([]string) (string, string, error) { return ufwNumberedFixture, "", nil }}
	result := decodeResult[DeleteResult](t, mustCall(t, ufwOnlyRuntime(t, runner), "firewall.deleteRule", `{"index":3,"dry_run":true}`))
	if result.Deleted.Action != ActionDeny || result.Deleted.Port != "8080:8090" {
		t.Fatalf("删除目标不符: %+v", result.Deleted)
	}
}

// TestDeleteIndexNotFound 不存在的编号返回 E_NOTFOUND。
func TestDeleteIndexNotFound(t *testing.T) {
	runner := &fakeRunner{handler: func([]string) (string, string, error) { return ufwNumberedFixture, "", nil }}
	_, perr := call(t, ufwOnlyRuntime(t, runner), "firewall.deleteRule", `{"index":99,"dry_run":true}`)
	requireCode(t, perr, pluginapi.E_NOTFOUND)
}

// TestDeleteRequiresUFW 只有 iptables 时 deleteRule 返回 E_UNSUPPORTED。
func TestDeleteRequiresUFW(t *testing.T) {
	runtime := newTestRuntime(t, &fakeRunner{}, BackendIptables)
	_, perr := call(t, runtime, "firewall.deleteRule", `{"index":1,"dry_run":true}`)
	requireCode(t, perr, pluginapi.E_UNSUPPORTED)
	_, perr = call(t, runtime, "firewall.allowPort", `{"port":80,"dry_run":true}`)
	requireCode(t, perr, pluginapi.E_UNSUPPORTED)
}

// TestWriteRequiresAdmin 缺少 system:admin 时写操作 E_UNAUTHORIZED，读方法仍可用。
func TestWriteRequiresAdmin(t *testing.T) {
	runner := &fakeRunner{handler: func(argv []string) (string, string, error) {
		if strings.Contains(strings.Join(argv, " "), "status verbose") {
			return ufwVerboseActive, "", nil
		}
		return ufwNumberedFixture, "", nil
	}}
	runtime, err := New(Options{Runner: runner, Resolve: stubResolver(BackendUFW)})
	if err != nil {
		t.Fatalf("构造执行面失败: %v", err)
	}
	for _, c := range []struct{ method, params string }{
		{"firewall.allowPort", `{"port":80,"dry_run":true}`},
		{"firewall.denyPort", `{"port":8080,"dry_run":true}`},
		{"firewall.deleteRule", `{"index":2,"dry_run":true}`},
	} {
		_, perr := call(t, runtime, c.method, c.params)
		requireCode(t, perr, pluginapi.E_UNAUTHORIZED)
	}
	mustCall(t, runtime, "firewall.status", "")
	mustCall(t, runtime, "firewall.rules", "")
	if len(runner.calls) != 2 {
		t.Fatalf("读方法应各调用一次，实际: %v", runner.commandStrings())
	}
}

// TestParamValidation 参数白名单与形状校验统一返回 E_INVALID。
func TestParamValidation(t *testing.T) {
	runtime := ufwOnlyRuntime(t, &fakeRunner{})
	cases := []struct {
		method string
		params string
	}{
		{"firewall.rules", `[]`},
		{"firewall.rules", `not-json`},
		{"firewall.allowPort", `{"port":0}`},
		{"firewall.allowPort", `{"port":65536}`},
		{"firewall.allowPort", `{"port":-1}`},
		{"firewall.allowPort", `{"port":22.5}`},
		{"firewall.allowPort", `{"port":80,"proto":"icmp"}`},
		{"firewall.allowPort", `{"port":80,"proto":"sctp"}`},
		{"firewall.allowPort", `{"port":80,"from":"example.com"}`},
		{"firewall.allowPort", `{"port":80,"from":"1.2.3.4;rm"}`},
		{"firewall.allowPort", `{"port":80,"comment":"` + strings.Repeat("a", 65) + `"}`},
		{"firewall.allowPort", `{"port":80,"comment":"bad\ncomment"}`},
		{"firewall.allowPort", `{"port":80,"dry_run":"yes"}`},
		{"firewall.allowPort", ``},
		{"firewall.denyPort", `{"port":8080,"from":"0.0.0.0/33"}`},
		{"firewall.deleteRule", `{"index":0}`},
		{"firewall.deleteRule", `{"index":-1}`},
		{"firewall.deleteRule", ``},
		{"firewall.status", `[]`},
	}
	for _, c := range cases {
		_, perr := call(t, runtime, c.method, c.params)
		if perr == nil || perr.Code != pluginapi.E_INVALID {
			t.Fatalf("Call(%s,%s) 错误=%+v，期望 E_INVALID", c.method, c.params, perr)
		}
	}
}

// TestUnknownMethod 未知方法返回 E_NOTFOUND。
func TestUnknownMethod(t *testing.T) {
	_, perr := call(t, ufwOnlyRuntime(t, &fakeRunner{}), "firewall.exec", `{}`)
	requireCode(t, perr, pluginapi.E_NOTFOUND)
}

// TestStatusErrorFieldKeepsFaultMessage status 把执行面故障写进 error 字段，不吞掉。
func TestStatusErrorFieldKeepsFaultMessage(t *testing.T) {
	runner := &fakeRunner{handler: func([]string) (string, string, error) {
		return "", "", NewFaultError(FaultTimeout, "ufw 超时")
	}}
	result := decodeResult[StatusResult](t, mustCall(t, ufwOnlyRuntime(t, runner), "firewall.status", ""))
	if !strings.Contains(result.Error, "超时") {
		t.Fatalf("error 未保留故障信息: %q", result.Error)
	}
}

// TestStatusUnreadableErrorIsNotProtocolError 非权限类失败同样落在 error 字段。
func TestStatusUnreadableErrorIsNotProtocolError(t *testing.T) {
	runner := &fakeRunner{handler: func([]string) (string, string, error) {
		return "", "cannot read /etc/ufw/user.rules", errors.New("exit status 1")
	}}
	raw, perr := call(t, ufwOnlyRuntime(t, runner), "firewall.status", "")
	if perr != nil {
		t.Fatalf("status 不应返回协议错误: %+v", perr)
	}
	result := decodeResult[StatusResult](t, raw, nil)
	if result.Available || !strings.Contains(result.Error, "cannot read") {
		t.Fatalf("状态不符: %+v", result)
	}
}
