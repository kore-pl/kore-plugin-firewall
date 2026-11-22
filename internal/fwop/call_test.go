package fwop

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestBusinessVerb 方法名归一化：firewall.<verb> 与裸 <verb> 都接受。
func TestBusinessVerb(t *testing.T) {
	cases := map[string]string{
		"firewall.rules": "rules", "firewall.allowPort": "allowPort",
		"rules": "rules", "allowPort": "allowPort",
	}
	for method, want := range cases {
		got, ok := businessVerb(method)
		if !ok || got != want {
			t.Fatalf("businessVerb(%q)=(%q,%v)，期望 (%q,true)", method, got, ok, want)
		}
	}
	if _, ok := businessVerb("firewall.exec"); ok {
		t.Fatal("firewall.exec 不应被接受")
	}
}

// TestCallResults 两方法正常路径返回结构化占位结果（applied=false）。
func TestCallResults(t *testing.T) {
	rules, perr := Call("firewall.rules", json.RawMessage(`{"action":"list"}`), nil)
	if perr != nil || !strings.Contains(string(rules), `"applied":false`) {
		t.Fatalf("firewall.rules 结果=%s err=%v", rules, perr)
	}
	port, perr := Call("firewall.allowPort", json.RawMessage(`{"port":8080,"protocol":"tcp"}`), nil)
	if perr != nil || !strings.Contains(string(port), `"applied":false`) {
		t.Fatalf("firewall.allowPort 结果=%s err=%v", port, perr)
	}
}

// TestCallParamValidation 非法参数形状、越界端口、非法协议均返回 E_INVALID。
func TestCallParamValidation(t *testing.T) {
	bad := []struct {
		method string
		params string
	}{
		{"firewall.rules", `[]`},
		{"firewall.allowPort", `not-json`},
		{"firewall.allowPort", `{"port":0,"protocol":"tcp"}`},
		{"firewall.allowPort", `{"port":65536,"protocol":"tcp"}`},
		{"firewall.allowPort", `{"port":-1,"protocol":"tcp"}`},
		{"firewall.allowPort", `{"port":80,"protocol":"icmp6"}`},
		{"firewall.allowPort", `{"port":80,"protocol":""}`},
		{"firewall.rules", `{"action":""}`},
		{"firewall.rules", `{"action":"list","chain":"bad/chain"}`},
	}
	for _, c := range bad {
		_, perr := Call(c.method, json.RawMessage(c.params), nil)
		if perr == nil || perr.Code != pluginapi.E_INVALID {
			t.Fatalf("Call(%s,%s) 错误=%v，期望 E_INVALID", c.method, c.params, perr)
		}
	}
}

// TestPortBoundaries 端口边界 1 与 65535 都合法，协议三值都合法。
func TestPortBoundaries(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		for _, port := range []int{1, 65535} {
			params, _ := json.Marshal(allowPortParams{Port: port, Protocol: protocol})
			if _, perr := Call("firewall.allowPort", params, nil); perr != nil {
				t.Fatalf("port=%d protocol=%s 意外错误: %v", port, protocol, perr)
			}
		}
	}
}

// TestCallUnknownMethod 未知方法返回 E_NOTFOUND。
func TestCallUnknownMethod(t *testing.T) {
	_, perr := Call("firewall.exec", json.RawMessage(`{}`), nil)
	if perr == nil || perr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("未知方法错误=%v，期望 E_NOTFOUND", perr)
	}
}
