package boundary

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/pengtang1024/kore-plugin-firewall/internal/fwop"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// 权限（permission / need_root）：本机以非 root 运行，真实执行 ufw / iptables
// 必然被内核拒绝。断言协议层返回 E_NEED_ROOT + 可操作 hint（ADR-0018），
// 而不是 panic、E_UNAUTHORIZED（401 会被前端读成"登录失效"）或静默成功。
// 这些用例不 mock 权限：直接使用真实 execRunner 与真实二进制探测路径。
func TestNonRootPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("当前以 root 运行：非 root 权限不足场景不可复现（CI 以非 root 运行）")
	}
	runtime := newRuntime(t, nil, nil, nil) // 真实命令 + 真实探测 + 无 root-action 通道

	t.Run("rules-真实读取被拒", func(t *testing.T) {
		result, perr := runtime.Call("firewall.rules", json.RawMessage(`{"backend":"ufw"}`))
		requireNeedRoot(t, result, perr)
	})

	t.Run("allowPort-真实写入被拒", func(t *testing.T) {
		result, perr := runtime.Call("firewall.allowPort", json.RawMessage(`{"port":8080,"proto":"tcp"}`))
		requireNeedRoot(t, result, perr)
	})

	t.Run("enable-无提权通道时显式失败", func(t *testing.T) {
		result, perr := runtime.Call("firewall.enable", json.RawMessage(`{"dry_run":false}`))
		requireNeedRoot(t, result, perr)
	})

	t.Run("status-降级为 available=false+E_NEED_ROOT", func(t *testing.T) {
		raw, perr := runtime.Call("firewall.status", json.RawMessage(`{}`))
		if perr != nil {
			t.Fatalf("status 不应返回协议错误（应降级展示原因）: %+v", perr)
		}
		var status fwop.StatusResult
		decodeResult(t, raw, &status)
		if status.Available {
			t.Fatalf("非 root 下 status 不应声称 available=true: %+v", status)
		}
		if status.ErrorCode != fwop.CodeNeedRoot {
			t.Fatalf("status.error_code=%q，期望 %q（error=%q）", status.ErrorCode, fwop.CodeNeedRoot, status.Error)
		}
		if status.Error == "" || status.Hint == "" {
			t.Fatalf("降级必须带可读原因与可操作 hint: %+v", status)
		}
	})
}

// requireNeedRoot 断言失败语义：无结果、E_NEED_ROOT、带 detail.hint 且不是 401。
func requireNeedRoot(t *testing.T, result json.RawMessage, perr *pluginapi.Error) {
	t.Helper()
	if perr == nil {
		t.Fatalf("非 root 下未返回错误（result=%s），疑似静默成功", result)
	}
	if result != nil {
		t.Fatalf("出错时不应带结果: %s", result)
	}
	if perr.Code != fwop.CodeNeedRoot {
		t.Fatalf("错误码=%q，期望 %q（message=%q）", perr.Code, fwop.CodeNeedRoot, perr.Message)
	}
	if perr.Code == pluginapi.E_UNAUTHORIZED {
		t.Fatal("权限不足不得误报 E_UNAUTHORIZED（401 语义）")
	}
	var detail struct {
		Hint string `json:"hint"`
	}
	if err := json.Unmarshal(perr.Detail, &detail); err != nil || detail.Hint == "" {
		t.Fatalf("E_NEED_ROOT 必须带 detail.hint（err=%v, detail=%s）", err, perr.Detail)
	}
	if !strings.Contains(detail.Hint, "kored") {
		t.Fatalf("hint 必须给出下一步（含 kored），实际 %q", detail.Hint)
	}
	if perr.Message == "" {
		t.Fatal("错误信息为空")
	}
}
