package boundary

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pengtang1024/kore-plugin-firewall/internal/fwop"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// 资源耗尽（resource exhaustion / ENOSPC / OOM / ulimit）：这里不做 FaultError 注入，
// 而是用真实内核错误命中执行面——1) 向 /dev/full 写规则文件立刻 ENOSPC（磁盘满）；
// 2) ulimit -v 限制 RLIMIT_AS 让子进程无法 mmap（内存耗尽）。
// 两种场景都必须转成协议错误（E_UPSTREAM），不得 panic 或静默成功。
// tmpfs 满需要 mount 权限（本机非 root，挂载即改宿主），故用 /dev/full 等价覆盖"写满"。
func TestResourceExhaustion(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skipf("缺少 /dev/full，无法真实注入 ENOSPC: %v", err)
	}

	t.Run("磁盘满-写规则文件", func(t *testing.T) {
		// 模拟 ufw 写 /etc/ufw/user.rules：真实写 /dev/full，内核立即返回 ENOSPC/EIO。
		script := writeScript(t, `#!/bin/sh
printf '%s\n' '-A ufw-user-input -p tcp --dport 8080 -j ACCEPT' >> /dev/full
`)
		runtime := newRuntime(t, nil, resolveScript(script), nil)
		result, perr := runtime.Call("firewall.allowPort", json.RawMessage(`{"port":8080,"proto":"tcp"}`))
		requireExecutionFailure(t, result, perr)
		lower := strings.ToLower(perr.Message)
		if !strings.Contains(lower, "i/o error") && !strings.Contains(lower, "no space") && !strings.Contains(lower, "enospc") {
			t.Fatalf("错误信息未保留真实写失败原因: %q", perr.Message)
		}
	})

	t.Run("内存耗尽-ulimit-v", func(t *testing.T) {
		python, err := exec.LookPath("python3")
		if err != nil {
			t.Skipf("缺少 python3，无法在 RLIMIT_AS 下制造真实 ENOMEM: %v", err)
		}
		script := writeScript(t, `#!/bin/sh
ulimit -v 8192 || exit 3
exec `+python+` -c 'x = bytearray(64 * 1024 * 1024)'
`)
		runtime := newRuntime(t, nil, resolveScript(script), nil)
		result, perr := runtime.Call("firewall.allowPort", json.RawMessage(`{"port":8081,"proto":"tcp"}`))
		requireExecutionFailure(t, result, perr)
		lower := strings.ToLower(perr.Message)
		memorySignals := []string{"memory", "map segment", "cannot allocate", "allocate", "memoryerror"}
		matched := false
		for _, signal := range memorySignals {
			if strings.Contains(lower, signal) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("错误信息未保留真实内存耗尽原因: %q", perr.Message)
		}
	})
}

// requireExecutionFailure 断言资源耗尽被转成显式协议错误：无结果、E_UPSTREAM、带命令上下文。
func requireExecutionFailure(t *testing.T, result json.RawMessage, perr *pluginapi.Error) {
	t.Helper()
	if perr == nil {
		t.Fatalf("资源耗尽后未返回错误（result=%s），疑似静默成功", result)
	}
	if result != nil {
		t.Fatalf("出错时不应带结果: %s", result)
	}
	if perr.Code != pluginapi.E_UPSTREAM {
		t.Fatalf("错误码=%q，期望 %q（message=%q）", perr.Code, pluginapi.E_UPSTREAM, perr.Message)
	}
	if perr.Message == "" || !strings.Contains(perr.Message, "执行") {
		t.Fatalf("错误信息缺少命令上下文: %q", perr.Message)
	}
}

// writeScript 在测试临时目录写一个可执行脚本（t.TempDir 自动清理，不留在工作区）。
func writeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exhaust.sh")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("写注入脚本失败: %v", err)
	}
	return path
}

// resolveScript 把 ufw 解析到注入脚本，其余后端保持不可见。
func resolveScript(path string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if name == fwop.BackendUFW {
			return path, true
		}
		return "", false
	}
}
