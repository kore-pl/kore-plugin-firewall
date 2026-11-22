package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// dispatchCall 经 dispatch 发一次业务请求并返回响应。
func dispatchCall(t *testing.T, method, params string) *pluginapi.Response {
	t.Helper()
	req := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: "id", ReqID: "r",
		Method: method, Params: json.RawMessage(params),
	}
	resp, shutdown := dispatch(req, testConfig(), testRuntime(t), testLogger())
	if shutdown {
		t.Fatalf("%s 不应触发 shutdown", method)
	}
	return resp
}

// TestDispatchMethods 五个方法经 dispatch 返回结构化结果。
func TestDispatchMethods(t *testing.T) {
	cases := []struct {
		method string
		params string
		want   []string
	}{
		{"firewall.status", ``, []string{`"backend":"ufw"`, `"available":true`, `"enabled":false`}},
		{"firewall.rules", `{"backend":"ufw"}`, []string{`"count":1`, `"port":80`}},
		{"firewall.allowPort", `{"port":8080,"dry_run":true}`, []string{`"applied":false`, `"dry_run":true`}},
		{"firewall.denyPort", `{"port":8080,"dry_run":true}`, []string{`"action":"deny"`}},
		{"firewall.deleteRule", `{"index":1,"dry_run":true}`, []string{`"--force"`, `"delete"`}},
	}
	for _, c := range cases {
		resp := dispatchCall(t, c.method, c.params)
		if resp.Error != nil {
			t.Fatalf("%s 意外错误: %v", c.method, resp.Error)
		}
		text := string(resp.Result)
		for _, want := range c.want {
			if !strings.Contains(text, want) {
				t.Fatalf("%s 结果=%s，未含 %q", c.method, text, want)
			}
		}
	}
}

// TestDispatchReject 非法参数与安全护栏经 dispatch 返回协议错误。
func TestDispatchReject(t *testing.T) {
	cases := []struct {
		method string
		params string
		code   string
	}{
		{"firewall.allowPort", `{"port":0}`, pluginapi.E_INVALID},
		{"firewall.allowPort", `{"port":65536}`, pluginapi.E_INVALID},
		{"firewall.allowPort", `{"port":80,"proto":"sctp"}`, pluginapi.E_INVALID},
		{"firewall.allowPort", `{"port":80,"from":"example.com"}`, pluginapi.E_INVALID},
		{"firewall.denyPort", `{"port":22}`, pluginapi.E_UNAUTHORIZED},
		{"firewall.denyPort", `{"port":22,"dry_run":true}`, pluginapi.E_UNAUTHORIZED},
		{"firewall.deleteRule", `{"index":0}`, pluginapi.E_INVALID},
		{"firewall.exec", `{}`, pluginapi.E_NOTFOUND},
	}
	for _, c := range cases {
		resp := dispatchCall(t, c.method, c.params)
		if resp.Error == nil || resp.Error.Code != c.code {
			t.Fatalf("%s 错误=%v，期望 %q", c.method, resp.Error, c.code)
		}
		if resp.Result != nil {
			t.Fatalf("%s 出错时不应带结果", c.method)
		}
	}
}

// TestDispatchSSHMessageExact deny 22 的错误文案必须与安全要求一字不差。
func TestDispatchSSHMessageExact(t *testing.T) {
	resp := dispatchCall(t, "firewall.denyPort", `{"port":22}`)
	want := "拒绝屏蔽 SSH 端口 22：这会导致你无法再连接到服务器。如确实需要，请先确认有其他登录方式"
	if resp.Error == nil || resp.Error.Message != want {
		t.Fatalf("SSH 保护文案不符: %+v", resp.Error)
	}
}

// TestPingResult kore.ping 返回 ready 状态。
func TestPingResult(t *testing.T) {
	req := &pluginapi.Request{Type: pluginapi.TypeRequest, ID: "id", ReqID: "r", Method: "kore.ping"}
	resp, _ := dispatch(req, testConfig(), testRuntime(t), testLogger())
	if !strings.Contains(string(resp.Result), `"status":"ready"`) {
		t.Fatalf("ping 结果=%s", resp.Result)
	}
}
