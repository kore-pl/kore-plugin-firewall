// Package boundary 是 firewall 插件的 production 判据① 边界用例集：
// 异常输入 / 并发 / 权限不足 / 资源耗尽 四类各至少一例。
//
// 与 tests/fault 的分工：fault 注入 FaultError 证明「错误 → 协议码」映射；
// boundary 用真实 goroutine、真实非 root 命令失败、真实 ENOSPC / ENOMEM
// 证明边界行为（不 panic、不静默成功、不误报 401）。
package boundary

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/pengtang1024/kore-plugin-firewall/internal/fwop"
)

// newRuntime 构造带 system:admin 与 22 保护端口的执行面；runner / resolve /
// rootAction 为 nil 时使用真实实现（真实命令 / 真实 root 探测 / 无提权通道）。
func newRuntime(t *testing.T, runner fwop.Runner, resolve func(string) (string, bool), rootAction fwop.RootActionFunc) *fwop.Runtime {
	t.Helper()
	runtime, err := fwop.New(fwop.Options{
		Capabilities: []string{fwop.CapabilityAdmin},
		SSHPorts:     []int{fwop.DefaultSSHPort},
		Runner:       runner,
		Resolve:      resolve,
		RootAction:   rootAction,
	})
	if err != nil {
		t.Fatalf("构造 Runtime 失败: %v", err)
	}
	return runtime
}

// resolveUFW 只认为 ufw 存在，避免测试机上 iptables 状态影响后端选择。
func resolveUFW(name string) (string, bool) {
	if name == fwop.BackendUFW {
		return "/usr/sbin/ufw", true
	}
	return "", false
}

// memRunner 是线程安全的内存 ufw 替身：只按固定 argv 模拟输出，不触达宿主防火墙。
// 写操作串行化在锁内，使并发用例的共享状态可解释；生产代码本身无共享可变状态。
type memRunner struct {
	mu       sync.Mutex
	rules    []string // 每条是 ufw status numbered 的规则体，如 "8080/tcp ALLOW IN Anywhere"
	switches int      // enable / disable 次数（root 场景走真实命令分支时计数）
}

// Run 实现 fwop.Runner。
func (m *memRunner) Run(argv []string) ([]byte, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	joined := strings.Join(argv, " ")
	switch {
	case strings.HasSuffix(joined, "status numbered"):
		var out strings.Builder
		out.WriteString("Status: active\n")
		for i, body := range m.rules {
			fmt.Fprintf(&out, "[%2d] %s\n", i+1, body)
		}
		return []byte(out.String()), nil, nil
	case strings.HasSuffix(joined, "status verbose"):
		return []byte("Status: active\nDefault: deny (incoming), allow (outgoing)\n"), nil, nil
	case strings.Contains(joined, " delete "):
		index, err := strconv.Atoi(argv[len(argv)-1])
		if err != nil || index < 1 || index > len(m.rules) {
			return nil, []byte("ERROR: rule not found"), fmt.Errorf("exit status 1")
		}
		m.rules = append(m.rules[:index-1], m.rules[index:]...)
		return nil, nil, nil
	case strings.Contains(joined, " allow ") || strings.Contains(joined, " deny "):
		m.rules = append(m.rules, ufwRuleBody(argv))
		return nil, nil, nil
	case strings.HasSuffix(joined, " enable") || strings.HasSuffix(joined, " disable"):
		m.switches++
		return nil, nil, nil
	}
	return nil, nil, nil
}

// ufwRuleBody 从 argv 还原一条合法 ufw 规则体，供后续 rules / delete 解析。
func ufwRuleBody(argv []string) string {
	action := strings.ToUpper(argv[1])
	proto, port := "tcp", "0"
	for i := 2; i+1 < len(argv); i++ {
		switch argv[i] {
		case "proto":
			proto = argv[i+1]
		case "port":
			port = argv[i+1]
		}
	}
	return fmt.Sprintf("%s/%s %s IN Anywhere", port, proto, action)
}

// ruleCount 返回当前内存规则条数（加锁，避免并发用例自身产生竞争）。
func (m *memRunner) ruleCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rules)
}

// switchCount 返回内存替身收到的启停次数。
func (m *memRunner) switchCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.switches
}

// countingRootAction 是线程安全的假内核提权通道：只计数、不执行任何特权动作。
type countingRootAction struct {
	mu    sync.Mutex
	calls int
}

// Do 实现 fwop.RootActionFunc。
func (c *countingRootAction) Do(string, []string) ([]byte, int, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return nil, 0, nil
}

// count 返回通道被调用次数。
func (c *countingRootAction) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// decodeResult 把 Call 的结果解码为 v，失败即判用例失败。
func decodeResult(t *testing.T, raw json.RawMessage, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("结果反序列化失败: %v（raw=%s）", err, raw)
	}
}
