package fwop

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// fakeRunner 记录每次调用并返回预置输出；handler 为 nil 时视为成功空输出。
type fakeRunner struct {
	calls   [][]string
	handler func(argv []string) (stdout, stderr string, err error)
}

func (f *fakeRunner) Run(argv []string) ([]byte, []byte, error) {
	f.calls = append(f.calls, append([]string(nil), argv...))
	if f.handler == nil {
		return nil, nil, nil
	}
	stdout, stderr, err := f.handler(argv)
	return []byte(stdout), []byte(stderr), err
}

// commandStrings 返回全部调用（空格连接），便于断言。
func (f *fakeRunner) commandStrings() []string {
	commands := make([]string, 0, len(f.calls))
	for _, argv := range f.calls {
		commands = append(commands, strings.Join(argv, " "))
	}
	return commands
}

// stubResolver 只解析给定后端，路径固定为 /usr/sbin/<name>。
func stubResolver(backends ...string) func(string) (string, bool) {
	available := make(map[string]bool, len(backends))
	for _, backend := range backends {
		available[backend] = true
	}
	return func(name string) (string, bool) {
		if available[name] {
			return "/usr/sbin/" + name, true
		}
		return "", false
	}
}

// newTestRuntime 构造测试执行面：默认带 system:admin 与 22 保护端口。
func newTestRuntime(t *testing.T, runner Runner, backends ...string) *Runtime {
	t.Helper()
	runtime, err := New(Options{
		Capabilities: []string{CapabilityAdmin},
		SSHPorts:     []int{DefaultSSHPort},
		Runner:       runner,
		Resolve:      stubResolver(backends...),
	})
	if err != nil {
		t.Fatalf("构造测试执行面失败: %v", err)
	}
	return runtime
}

// paramsRaw 把测试里的 JSON 文本转成调用参数；空串表示省略参数。
func paramsRaw(params string) json.RawMessage {
	if params == "" {
		return nil
	}
	return json.RawMessage(params)
}

// mustCall 要求调用成功并返回结果原文。
func mustCall(t *testing.T, runtime *Runtime, method, params string) json.RawMessage {
	t.Helper()
	raw, perr := runtime.Call(method, paramsRaw(params))
	if perr != nil {
		t.Fatalf("%s 意外失败: %+v", method, perr)
	}
	return raw
}

// decodeResult 要求调用成功并把结果解码到 T；perrs 为可选错误参数。
func decodeResult[T any](t *testing.T, raw json.RawMessage, perrs ...*pluginapi.Error) T {
	t.Helper()
	for _, perr := range perrs {
		if perr != nil {
			t.Fatalf("调用意外失败: %+v", perr)
		}
	}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("解码结果失败: %v（原文=%s）", err, raw)
	}
	return value
}

// requireCode 断言协议错误码，并返回错误体（便于再断言 message）。
func requireCode(t *testing.T, perr *pluginapi.Error, code string) *pluginapi.Error {
	t.Helper()
	if perr == nil {
		t.Fatalf("期望错误码 %s，实际无错误", code)
	}
	if perr.Code != code {
		t.Fatalf("错误码=%s，期望 %s（message=%q）", perr.Code, code, perr.Message)
	}
	return perr
}

// 以下 fixture 来自 ufw 0.36 / iptables 1.8 的真实输出形态（C locale）。

const ufwVerboseActive = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere                   # ssh
80,443/tcp                 ALLOW IN    Anywhere
8080:8090/tcp              ALLOW IN    10.0.0.0/8
Anywhere                   DENY IN     203.0.113.7
22/tcp (v6)                ALLOW IN    Anywhere (v6)              # ssh
`

const ufwVerboseInactive = "Status: inactive\n"

const ufwNumberedFixture = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # ssh
[ 2] 80,443/tcp                 ALLOW IN    Anywhere
[ 3] 8080:8090/tcp              DENY IN     10.0.0.0/8
[ 4] Anywhere                   REJECT IN   203.0.113.7
[ 5] 22/tcp (v6)                ALLOW IN    Anywhere (v6)              # ssh
[ 6] 22/tcp on eth0             ALLOW IN    Anywhere
[ 7] 53/udp                     LIMIT IN    Anywhere                   # dns rate
`

const iptablesSFixture = `-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N DOCKER
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -s 10.0.0.0/8 -p udp -m udp --dport 53 -j ACCEPT
-A INPUT -m multiport -p tcp --dports 80,443 -j ACCEPT
-A INPUT -p tcp --dport 3306 -j DROP
-A INPUT -j REJECT --reject-with icmp-port-unreachable
-A INPUT -j DOCKER-USER
-A FORWARD -j DOCKER
-A OUTPUT -j ACCEPT
`

// permissionError 模拟非 root 下的命令失败（C locale 文案）。
func permissionError() (string, string, error) {
	return "", "ERROR: You need to be root to run this script", errors.New("exit status 1")
}
