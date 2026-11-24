package boundary

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/pengtang1024/kore-plugin-firewall/internal/fwop"
)

// 并发（concurrency / race）：真 goroutine 并发调用同一个 Runtime，
// 覆盖「并发增删规则」与「并发启停」。配合 go test -race 断言无数据竞争；
// 同时断言每个调用恰好返回 result 或 error（不静默），写操作计数守恒。
func TestConcurrentRuleOps(t *testing.T) {
	runner := &memRunner{}
	runtime := newRuntime(t, runner, resolveUFW, nil)

	const (
		goroutines = 24
		iterations = 12
	)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		added    int
		failures []string
	)
	record := func(message string) {
		mu.Lock()
		failures = append(failures, message)
		mu.Unlock()
	}

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				port := 20000 + g*iterations + i
				var method, params string
				switch i % 5 {
				case 0:
					method, params = "firewall.allowPort", fmt.Sprintf(`{"port":%d,"proto":"tcp"}`, port)
				case 1:
					method, params = "firewall.denyPort", fmt.Sprintf(`{"port":%d,"proto":"udp"}`, port)
				case 2:
					method, params = "firewall.rules", `{"backend":"ufw"}`
				case 3:
					method, params = "firewall.status", `{}`
				default:
					verb := "enable"
					if (g+i)%2 == 0 {
						verb = "disable"
					}
					method, params = "firewall."+verb, `{"dry_run":true}`
				}

				result, perr := runtime.Call(method, json.RawMessage(params))
				if perr == nil && result == nil {
					record(fmt.Sprintf("%s 同时返回 nil result 与 nil error（静默失败）", method))
					continue
				}
				if perr != nil {
					if perr.Code == "" || perr.Message == "" {
						record(fmt.Sprintf("%s 错误体不完整: %+v", method, perr))
					}
					continue
				}
				if method == "firewall.allowPort" || method == "firewall.denyPort" {
					var write fwop.WriteResult
					if err := json.Unmarshal(result, &write); err != nil {
						record(fmt.Sprintf("%s 结果不可解码: %v", method, err))
						continue
					}
					if !write.Applied {
						record(fmt.Sprintf("%s 成功返回但 Applied=false", method))
						continue
					}
					mu.Lock()
					added++
					mu.Unlock()
				}
			}
		}(g)
	}
	wg.Wait()

	if len(failures) > 0 {
		t.Fatalf("并发调用出现 %d 个异常:\n%s", len(failures), strings.Join(failures, "\n"))
	}
	if got := runner.ruleCount(); got != added {
		t.Fatalf("最终规则数=%d，成功写操作=%d：并发写丢失或重复", got, added)
	}
}

// TestConcurrentSwitch 真并发启停：16 个 goroutine 交替 enable / disable。
// 非 root 走注入的 root-action 通道，root 走真实命令分支——两条路径都必须
// 按调用次数幂等记账（ufw 启停天然幂等），且每次返回 Applied=true。
func TestConcurrentSwitch(t *testing.T) {
	runner := &memRunner{}
	rootAction := &countingRootAction{}
	runtime := newRuntime(t, runner, resolveUFW, rootAction.Do)

	const (
		goroutines   = 16
		perGoroutine = 10
	)
	var wg sync.WaitGroup
	failures := make(chan string, goroutines*perGoroutine)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				method := "firewall.enable"
				if (g+i)%2 == 1 {
					method = "firewall.disable"
				}
				result, perr := runtime.Call(method, json.RawMessage(`{"dry_run":false}`))
				if perr != nil {
					failures <- fmt.Sprintf("%s 返回错误: %+v", method, perr)
					continue
				}
				var write fwop.WriteResult
				if err := json.Unmarshal(result, &write); err != nil {
					failures <- fmt.Sprintf("%s 结果不可解码: %v", method, err)
					continue
				}
				if !write.Applied {
					failures <- fmt.Sprintf("%s 成功返回但 Applied=false", method)
				}
			}
		}(g)
	}
	wg.Wait()
	close(failures)

	var collected []string
	for failure := range failures {
		collected = append(collected, failure)
	}
	if len(collected) > 0 {
		t.Fatalf("并发启停出现 %d 个异常:\n%s", len(collected), strings.Join(collected, "\n"))
	}
	want := goroutines * perGoroutine
	if got := rootAction.count() + runner.switchCount(); got != want {
		t.Fatalf("启停执行次数=%d（root-action=%d + 命令=%d），期望 %d",
			got, rootAction.count(), runner.switchCount(), want)
	}
}
