package main

import (
	"encoding/json"
	"os"
	"testing"
)

// TestMethodCapabilitiesCoverBusinessVerbs 锁定 info.json 的 method_capabilities：
// 业务动词必须全量声明、读写分级正确，且不得声明不存在的动词（表驱动）。
func TestMethodCapabilitiesCoverBusinessVerbs(t *testing.T) {
	raw, err := os.ReadFile("info.json")
	if err != nil {
		t.Fatalf("读取 info.json 失败: %v", err)
	}
	var info struct {
		MethodCapabilities map[string]string `json:"method_capabilities"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("info.json 解析失败: %v", err)
	}
	want := map[string]string{
		"firewall.status":     "system:read",
		"firewall.rules":      "system:read",
		"firewall.allowPort":  "system:admin",
		"firewall.denyPort":   "system:admin",
		"firewall.deleteRule": "system:admin",
		"firewall.enable":     "system:admin",
		"firewall.disable":    "system:admin",
		"firewall.config.get": "system:read",
		"firewall.config.set": "system:admin",
	}
	if len(info.MethodCapabilities) != len(want) {
		t.Fatalf("method_capabilities 条数=%d，期望 %d：%v", len(info.MethodCapabilities), len(want), info.MethodCapabilities)
	}
	for method, capability := range want {
		got, ok := info.MethodCapabilities[method]
		if !ok {
			t.Fatalf("缺少 %s 的能力声明", method)
		}
		if got != capability {
			t.Fatalf("%s 能力=%q，期望 %q", method, got, capability)
		}
	}
}
