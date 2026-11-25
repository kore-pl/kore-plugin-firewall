package fwop

import (
	"encoding/json"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestSwitchZeroParamWriteIsNotInvalid 是 G-33 判据 A1（写操作零参数不得返回
// E_INVALID）的 in-process 回归证明。
//
// 为什么选 firewall.enable / firewall.disable：它们是 info.json 声明的
// system:admin 写方法（真实会切换宿主 ufw 开关），而入参 switchParams 只有
// 一个可选字段 dry_run —— 空对象 {} 就是它们契约上最诚实、最 irreducible 的
// 调用形态：不指定 dry_run 时按配置默认（本测试为 false），直接走写执行面。
// 本插件其余写方法（allowPort / denyPort / deleteRule）都必须显式给出 port /
// index，传 {} 返回 E_INVALID「缺少必填参数」是正确提示，强行让它成功等于
// 替用户猜端口/猜规则，是 UX 事故；因此不拿它们做零参数断言。
//
// 全程 in-process + fake 级替身：newSwitchRuntime 注入 fakeRunner + stubResolver，
// 并注入记录型 rootAction 假通道 —— 非 root（测试进程 uid≠0）下 enable/disable
// 经该假通道执行，只记录 action id、不碰真实 ufw / 系统状态 / 网络 / root（G-29）。
// 执行面命中由「假通道记录到 ufw-enable / ufw-disable」+ 结果 Applied=true 证明；
// 断言结果不是 E_INVALID（允许 success / E_NEED_ROOT / E_UNAVAILABLE /
// E_CONFIRM_REQUIRED，本用例真实契约是 success）。
func TestSwitchZeroParamWriteIsNotInvalid(t *testing.T) {
	var actions []string
	var argCalls int
	rt := newSwitchRuntime(t, func(id string, args []string) ([]byte, int, error) {
		actions = append(actions, id)
		argCalls += len(args)
		return nil, 0, nil
	})

	for _, tc := range []struct{ method, wantVerb string }{
		{"firewall.enable", "enable"},
		{"firewall.disable", "disable"},
	} {
		t.Run(tc.method, func(t *testing.T) {
			// 与真实请求同一入口 Call()：零参数写操作（空对象，无任何字段）。
			raw, perr := rt.Call(tc.method, json.RawMessage(`{}`))
			if perr != nil {
				if perr.Code == pluginapi.E_INVALID {
					t.Fatalf("%s 零参数写返回 E_INVALID（违反 G-33 A1）: %s", tc.method, perr.Message)
				}
				if perr.Code != CodeNeedRoot && perr.Code != "E_UNAVAILABLE" && perr.Code != "E_CONFIRM_REQUIRED" {
					t.Fatalf("%s 零参数写返回不允许的错误: code=%s message=%s", tc.method, perr.Code, perr.Message)
				}
				t.Logf("%s 零参数写返回允许的环境性错误 code=%s message=%s", tc.method, perr.Code, perr.Message)
				return
			}
			result := decodeWrite(t, raw)
			if !result.Applied || result.DryRun || result.Backend != BackendUFW {
				t.Fatalf("%s 零参数写结果不符: %+v", tc.method, result)
			}
			if len(result.Command) != 2 || result.Command[1] != tc.wantVerb {
				t.Fatalf("%s 零参数写命令不符: %v", tc.method, result.Command)
			}
		})
	}

	// 证明写执行面真的被走到：假 root-action 通道收到且只收到两个固定 action id，
	// 且没有附带参数；fakeRunner 零调用（非 root 不直接跑命令、不碰宿主防火墙）。
	want := []string{"ufw-enable", "ufw-disable"}
	if len(actions) != len(want) {
		t.Fatalf("假通道调用次数=%d，期望 %d：%v", len(actions), len(want), actions)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Fatalf("假通道 action id 不符: got %v want %v", actions, want)
		}
	}
	if argCalls != 0 {
		t.Fatalf("enable/disable 不应附带参数，实际 %d 个", argCalls)
	}
	if calls := rt.runner.(*fakeRunner).calls; len(calls) != 0 {
		t.Fatalf("非 root 不得直接执行命令（fake 记录）: %v", calls)
	}
}
