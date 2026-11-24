package boundary

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// 异常输入（invalid input / malformed params）：协议边界上的非法端口、非法协议、
// 非法来源（含命令注入字符）、超长注释、非法链名（backend）、非法规则编号、
// 未知方法与坏 JSON 都必须转成显式协议错误，而不是 panic 或落到执行面。
func TestInvalidInputBoundary(t *testing.T) {
	runtime := newRuntime(t, &memRunner{}, resolveUFW, nil)
	longComment, err := json.Marshal(strings.Repeat("a", 65))
	if err != nil {
		t.Fatalf("构造超长注释失败: %v", err)
	}

	cases := []struct {
		name     string
		method   string
		params   json.RawMessage
		wantCode string
	}{
		{"非法参数-缺参数对象", "firewall.allowPort", nil, pluginapi.E_INVALID},
		{"非法参数-坏 JSON", "firewall.allowPort", json.RawMessage(`{"port":`), pluginapi.E_INVALID},
		{"非法参数-非对象", "firewall.allowPort", json.RawMessage(`[]`), pluginapi.E_INVALID},
		{"非法参数-端口下界", "firewall.allowPort", json.RawMessage(`{"port":0}`), pluginapi.E_INVALID},
		{"非法参数-端口上界", "firewall.allowPort", json.RawMessage(`{"port":65536}`), pluginapi.E_INVALID},
		{"非法规则-协议", "firewall.allowPort", json.RawMessage(`{"port":8080,"proto":"icmp"}`), pluginapi.E_INVALID},
		{"非法规则-来源注入", "firewall.allowPort", json.RawMessage(`{"port":8080,"from":"1.2.3.4; rm -rf /"}`), pluginapi.E_INVALID},
		{"非法规则-来源主机名", "firewall.allowPort", json.RawMessage(`{"port":8080,"from":"example.com"}`), pluginapi.E_INVALID},
		{"非法规则-注释超长", "firewall.allowPort", json.RawMessage(fmt.Sprintf(`{"port":8080,"comment":%s}`, longComment)), pluginapi.E_INVALID},
		{"非法链名-backend", "firewall.rules", json.RawMessage(`{"backend":"nft"}`), pluginapi.E_INVALID},
		{"非法规则编号", "firewall.deleteRule", json.RawMessage(`{"index":0}`), pluginapi.E_INVALID},
		{"未知方法", "firewall.nftList", json.RawMessage(`{}`), pluginapi.E_NOTFOUND},
		{"SSH 护栏目", "firewall.denyPort", json.RawMessage(`{"port":22}`), pluginapi.E_UNAUTHORIZED},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, perr := runtime.Call(c.method, c.params)
			if perr == nil {
				t.Fatalf("%s 非法输入未返回错误（result=%s）", c.method, result)
			}
			if result != nil {
				t.Fatalf("%s 出错时不应带结果: %s", c.method, result)
			}
			if perr.Code != c.wantCode {
				t.Fatalf("%s 错误码=%q，期望 %q（message=%q）", c.method, perr.Code, c.wantCode, perr.Message)
			}
			if perr.Message == "" {
				t.Fatalf("%s 错误信息为空", c.method)
			}
		})
	}
}

// TestInvalidInputReachesNoExecution 证明非法输入在校验层就被拦下：
// 若落到执行面，内存替身会记录规则，这里必须为 0。
func TestInvalidInputReachesNoExecution(t *testing.T) {
	runner := &memRunner{}
	runtime := newRuntime(t, runner, resolveUFW, nil)
	for _, params := range []string{
		`{"port":0}`,
		`{"port":8080,"proto":"sctp"}`,
		`{"port":8080,"from":"1.2.3.4|cat /etc/passwd"}`,
	} {
		if _, perr := runtime.Call("firewall.allowPort", json.RawMessage(params)); perr == nil {
			t.Fatalf("非法参数 %s 未被拦截", params)
		}
	}
	if got := runner.ruleCount(); got != 0 {
		t.Fatalf("非法输入触发了执行面写入：规则数=%d，期望 0", got)
	}
}
