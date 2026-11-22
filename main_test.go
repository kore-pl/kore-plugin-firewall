package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// testConfig 构造握手与会话循环共用的一致配置（不依赖环境变量）。
func testConfig() config {
	return config{
		id:           "firewall",
		version:      "0.1.0",
		requiresKore: ">=0.1.0 <0.2.0",
		capabilities: []string{"system:admin"},
		startedAt:    time.Now(),
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func readFrame(t *testing.T, conn net.Conn) any {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
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

func readRequest(t *testing.T, conn net.Conn) *pluginapi.Request {
	t.Helper()
	request, ok := readFrame(t, conn).(*pluginapi.Request)
	if !ok {
		t.Fatal("帧类型不是 request")
	}
	return request
}

// readResponse 是配对读帧助手：每个发往插件的 shutdown 请求都必须调用它读回响应帧。
// net.Pipe 无缓冲，若不读响应，写入方会永久阻塞在 serve 的 WriteJSON 上。
func readResponse(t *testing.T, conn net.Conn, wantID string) *pluginapi.Response {
	t.Helper()
	response, ok := readFrame(t, conn).(*pluginapi.Response)
	if !ok {
		t.Fatal("响应帧类型不是 response")
	}
	if response.ID != wantID {
		t.Fatalf("响应 id=%q，期望 %q", response.ID, wantID)
	}
	return response
}

func writeResponse(t *testing.T, conn net.Conn, id, reqID string, result json.RawMessage) {
	t.Helper()
	if err := pluginapi.WriteJSON(conn, &pluginapi.Response{
		Type: pluginapi.TypeResponse, ID: id, ReqID: reqID, Result: result,
	}); err != nil {
		t.Fatalf("写响应失败: %v", err)
	}
}

// TestHandshake 校验 hello 首帧字段与三步握手。
func TestHandshake(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	done := make(chan error, 1)
	go func() { done <- handshake(pluginConn, testConfig()); _ = pluginConn.Close() }()

	request := readRequest(t, kernelConn)
	if request.Method != helloMethod {
		t.Fatalf("首帧方法=%q，期望 %q", request.Method, helloMethod)
	}
	var params helloParams
	if err := json.Unmarshal(request.Params, &params); err != nil {
		t.Fatalf("解析 hello 参数失败: %v", err)
	}
	if params.PluginID != "firewall" || params.ID != "firewall" {
		t.Fatalf("plugin_id/id=%q/%q，期望 firewall", params.PluginID, params.ID)
	}
	if params.Protocol != pluginapi.Protocol || params.Version != "0.1.0" {
		t.Fatalf("protocol/version=%q/%q 不符合 §5", params.Protocol, params.Version)
	}
	if params.PID != os.Getpid() {
		t.Fatalf("pid=%d，期望 %d", params.PID, os.Getpid())
	}
	result, err := json.Marshal(helloResult{OK: true, Protocol: pluginapi.Protocol})
	if err != nil {
		t.Fatalf("序列化握手响应失败: %v", err)
	}
	writeResponse(t, kernelConn, request.ID, request.ReqID, result)
	if err := <-done; err != nil {
		t.Fatalf("握手返回错误: %v", err)
	}
}

// TestServeShutdown 会话循环收到 kore.shutdown 后回响应帧再优雅退出。
// 硬约束：此处必须配对读响应帧，否则 net.Pipe 无缓冲会导致 serve 写阻塞。
func TestServeShutdown(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	done := make(chan error, 1)
	go func() { done <- serve(pluginConn, testConfig(), testLogger()); _ = pluginConn.Close() }()

	request := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: "id-shutdown", ReqID: "r-shutdown", Method: "kore.shutdown",
	}
	if err := pluginapi.WriteJSON(kernelConn, request); err != nil {
		t.Fatalf("写 shutdown 请求失败: %v", err)
	}
	response := readResponse(t, kernelConn, "id-shutdown")
	if response.Error != nil {
		t.Fatalf("shutdown 响应带错误: %v", response.Error)
	}
	if err := <-done; err != nil {
		t.Fatalf("serve 返回错误: %v", err)
	}
}

// TestServeBusinessThenShutdown 业务请求与 shutdown 串联，每个请求都配对读一帧响应。
func TestServeBusinessThenShutdown(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	done := make(chan error, 1)
	go func() { done <- serve(pluginConn, testConfig(), testLogger()); _ = pluginConn.Close() }()

	requests := []*pluginapi.Request{
		{Type: pluginapi.TypeRequest, ID: "id-rules", ReqID: "r-rules", Method: "firewall.rules", Params: json.RawMessage(`{"action":"list"}`)},
		{Type: pluginapi.TypeRequest, ID: "id-port", ReqID: "r-port", Method: "firewall.allowPort", Params: json.RawMessage(`{"port":8080,"protocol":"tcp"}`)},
		{Type: pluginapi.TypeRequest, ID: "id-stop", ReqID: "r-stop", Method: "kore.shutdown"},
	}
	for _, req := range requests {
		if err := pluginapi.WriteJSON(kernelConn, req); err != nil {
			t.Fatalf("写 %s 请求失败: %v", req.Method, err)
		}
		resp := readResponse(t, kernelConn, req.ID)
		if resp.Error != nil {
			t.Fatalf("%s 响应带错误: %v", req.Method, resp.Error)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("serve 返回错误: %v", err)
	}
}
