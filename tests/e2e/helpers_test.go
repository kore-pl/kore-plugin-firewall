//go:build linux

// Package e2e 用真实插件二进制 + 假内核 UDS 做只读端到端验证。
// 本包刻意不执行任何写操作：写路径只通过 dry_run 与单元测试覆盖。
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// buildPlugin 构建真实插件二进制到临时目录。
func buildPlugin(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "firewall-plugin")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("构建插件失败: %v\n%s", err, out)
	}
	return binary
}

// startPlugin 以协议环境变量启动插件进程；stderr 收集起来便于失败时定位。
func startPlugin(t *testing.T, binary, socket string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	stderr := &bytes.Buffer{}
	process := exec.Command(binary)
	process.Env = append(os.Environ(),
		"KORE_PLUGIN_SOCK="+socket,
		"KORE_PLUGIN_ID=firewall",
		"KORE_PLUGIN_TOKEN=e2e-token",
	)
	process.Stdout = io.Discard
	process.Stderr = stderr
	if err := process.Start(); err != nil {
		t.Fatalf("启动插件失败: %v", err)
	}
	t.Cleanup(func() {
		if process.ProcessState == nil {
			_ = process.Process.Kill()
			_, _ = process.Process.Wait()
		}
	})
	return process, stderr
}

// handshake 读 kore.hello 并回 ok 响应。
func handshake(t *testing.T, conn net.Conn) {
	t.Helper()
	request := readRequest(t, conn)
	if request.Method != "kore.hello" {
		t.Fatalf("首帧应为 kore.hello，实际 %s", request.Method)
	}
	response := &pluginapi.Response{
		Type: pluginapi.TypeResponse, ID: request.ID, ReqID: request.ReqID,
		Result: json.RawMessage(`{"ok":true,"protocol":"kore.plugin.v1"}`),
	}
	if err := pluginapi.WriteJSON(conn, response); err != nil {
		t.Fatalf("回写 hello 失败: %v", err)
	}
}

// request 发送一次方法调用并读回响应。
func request(t *testing.T, conn net.Conn, id, method string, params any) *pluginapi.Response {
	t.Helper()
	var raw json.RawMessage
	if params != nil {
		encoded, err := json.Marshal(params)
		if err != nil {
			t.Fatalf("序列化 %s 参数失败: %v", method, err)
		}
		raw = encoded
	}
	req := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: id, ReqID: "r-" + id, Method: method, Params: raw,
	}
	if err := pluginapi.WriteJSON(conn, req); err != nil {
		t.Fatalf("发送 %s 失败: %v", method, err)
	}
	return readResponse(t, conn)
}

// mustCall 要求调用成功并返回结果原文。
func mustCall(t *testing.T, conn net.Conn, id, method string, params any) json.RawMessage {
	t.Helper()
	resp := request(t, conn, id, method, params)
	if resp.Error != nil {
		t.Fatalf("%s 意外失败: %+v", method, resp.Error)
	}
	return resp.Result
}

// readRequest 读一帧并断言是 request。
func readRequest(t *testing.T, conn net.Conn) *pluginapi.Request {
	t.Helper()
	env := readFrame(t, conn)
	request, ok := env.(*pluginapi.Request)
	if !ok {
		t.Fatalf("帧类型是 %T，不是 request", env)
	}
	return request
}

// readResponse 读一帧并断言是 response。
func readResponse(t *testing.T, conn net.Conn) *pluginapi.Response {
	t.Helper()
	env := readFrame(t, conn)
	response, ok := env.(*pluginapi.Response)
	if !ok {
		t.Fatalf("帧类型是 %T，不是 response", env)
	}
	return response
}

// readFrame 读一帧并解码信封。
func readFrame(t *testing.T, conn net.Conn) any {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	payload, err := pluginapi.ReadFrame(conn, pluginapi.MaxFrameSize)
	if err != nil {
		t.Fatalf("读帧失败: %v", err)
	}
	env, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		t.Fatalf("解码帧失败: %v", err)
	}
	return env
}

// waitPlugin 等待插件进程退出；超时视为失败。
func waitPlugin(t *testing.T, process *exec.Cmd, timeout time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("插件退出码非 0: %v", err)
		}
	case <-time.After(timeout):
		t.Fatalf("插件在 %s 内未退出", timeout)
	}
}

// probeBinary 返回 ufw / iptables 的真实路径，找不到返回空串。
func probeBinary(name string) string {
	candidates := map[string][]string{
		"ufw":      {"/usr/sbin/ufw", "/sbin/ufw", "/usr/bin/ufw"},
		"iptables": {"/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"},
	}
	for _, path := range candidates[name] {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	return ""
}

// fileState 是规则文件的元信息快照（非 root 读不到内容，但 stat 可用）。
type fileState struct {
	Exists  bool
	Size    int64
	ModTime int64
}

// systemSnapshot 是 dry-run 前后用于对比的宿主防火墙视图。
type systemSnapshot struct {
	UFWStatus string
	IPTables  string
	UserRules fileState
	User6     fileState
}

// captureSnapshot 采集 ufw status verbose、iptables -S 与 ufw 规则文件元信息。
// 全部只读；命令失败也保留输出，保证 diff 能覆盖错误文案变化。
func captureSnapshot() systemSnapshot {
	return systemSnapshot{
		UFWStatus: probeCommand("ufw", "status", "verbose"),
		IPTables:  probeCommand("iptables", "-S"),
		UserRules: statFile("/etc/ufw/user.rules"),
		User6:     statFile("/etc/ufw/user6.rules"),
	}
}

// probeCommand 以 C locale 执行探测命令并返回 "argv|exit|output" 文本。
func probeCommand(name string, args ...string) string {
	path := probeBinary(name)
	if path == "" {
		return fmt.Sprintf("%s|missing", name)
	}
	command := exec.Command(path, args...)
	command.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	out, err := command.CombinedOutput()
	return fmt.Sprintf("%s %v|exit=%v|%s", path, args, err, out)
}

// statFile 采集文件大小与 mtime；不存在时 Exists=false。
func statFile(path string) fileState {
	info, err := os.Stat(path)
	if err != nil {
		return fileState{}
	}
	return fileState{Exists: true, Size: info.Size(), ModTime: info.ModTime().UnixNano()}
}
