// Package fault 对 firewall 插件做四类故障注入，验证方法级错误返回。
// 每个用例向 fwop.Runtime 注入返回 FaultError 的命令执行器，断言方法返回的协议错误码。
package fault

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pengtang1024/kore-plugin-firewall/internal/fwop"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// faultRunner 让每个外部命令都以注入的故障失败，模拟四类运行时故障。
type faultRunner struct {
	kind fwop.FaultKind
}

func (f faultRunner) Run(argv []string) ([]byte, []byte, error) {
	return nil, nil, fwop.NewFaultError(f.kind, strings.Join(argv, " ")+" 执行面故障")
}

// healthyRunner 返回最小真实输出，供无故障 sanity 使用。
type healthyRunner struct{}

func (healthyRunner) Run(argv []string) ([]byte, []byte, error) {
	joined := strings.Join(argv, " ")
	switch {
	case strings.HasSuffix(joined, "status numbered"):
		return []byte("Status: active\n[ 1] 80/tcp                     ALLOW IN    Anywhere\n"), nil, nil
	case strings.HasSuffix(joined, "status verbose"):
		return []byte("Status: active\n"), nil, nil
	case strings.HasSuffix(joined, "-S"):
		return []byte("-P INPUT ACCEPT\n"), nil, nil
	}
	return nil, nil, nil
}

// runtimeWith 构造带 system:admin 与 22 保护端口的执行面。
func runtimeWith(runner fwop.Runner) *fwop.Runtime {
	runtime, err := fwop.New(fwop.Options{
		Capabilities: []string{fwop.CapabilityAdmin},
		SSHPorts:     []int{fwop.DefaultSSHPort},
		Runner:       runner,
		Resolve: func(name string) (string, bool) {
			if name == fwop.BackendUFW || name == fwop.BackendIptables {
				return "/usr/sbin/" + name, true
			}
			return "", false
		},
	})
	if err != nil {
		panic(err)
	}
	return runtime
}

// methods 是故障注入覆盖的方法及其合法参数（非 dry-run，确保执行面被触达）。
var methods = []struct {
	name   string
	method string
	params string
}{
	{"rules", "firewall.rules", `{"backend":"ufw"}`},
	{"allowPort", "firewall.allowPort", `{"port":8080,"proto":"tcp"}`},
	{"denyPort", "firewall.denyPort", `{"port":8080,"proto":"tcp"}`},
	{"deleteRule", "firewall.deleteRule", `{"index":1}`},
}

// assertFault 对每个方法注入故障，断言返回 nil 结果 + 预期的协议错误码与类别关键词。
func assertFault(t *testing.T, kind fwop.FaultKind, wantCode, wantHint string) {
	t.Helper()
	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			result, perr := runtimeWith(faultRunner{kind: kind}).Call(m.method, json.RawMessage(m.params))
			if perr == nil {
				t.Fatalf("%s 注入 %s 后未返回错误（结果=%s）", m.method, kind, result)
			}
			if result != nil {
				t.Fatalf("%s 出错时不应带结果: %s", m.method, result)
			}
			if perr.Code != wantCode {
				t.Fatalf("%s 错误码=%q，期望 %q（message=%q）", m.method, perr.Code, wantCode, perr.Message)
			}
			if !strings.Contains(perr.Message, wantHint) {
				t.Fatalf("%s 错误信息 %q 未含类别关键词 %q", m.method, perr.Message, wantHint)
			}
		})
	}
}

// sanityNoFault 验证无故障时四个方法正常返回，证明故障断言不是"永远失败"的假通过。
func sanityNoFault(t *testing.T) {
	t.Helper()
	runtime := runtimeWith(healthyRunner{})
	for _, m := range methods {
		result, perr := runtime.Call(m.method, json.RawMessage(m.params))
		if perr != nil {
			t.Fatalf("无故障时 %s 意外返回错误: %v", m.method, perr)
		}
		if len(result) == 0 {
			t.Fatalf("无故障时 %s 返回空结果", m.method)
		}
	}
}

// verifyErrorContract 断言错误体是标准协议结构（含 code 字段）。
func verifyErrorContract(t *testing.T, perr *pluginapi.Error) {
	t.Helper()
	if perr == nil {
		t.Fatal("错误体为 nil")
	}
	if perr.Code == "" || perr.Message == "" {
		t.Fatalf("错误体字段不完整: %+v", perr)
	}
}
