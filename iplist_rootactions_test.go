package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// maxRootActions 是内核协议上限（kore internal/core/registry maxRootActions）：
// 超了包能打出来、却装不上（store/install 会在 info.json 校验阶段拒绝）。
const maxRootActions = 16

// TestIPRootActionsSchema 复核全部 root_actions 的 schema 与受控形状。
func TestIPRootActionsSchema(t *testing.T) {
	raw, err := os.ReadFile("info.json")
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		RootActions []pluginapi.RootAction `json:"root_actions"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatal(err)
	}
	if len(info.RootActions) > maxRootActions {
		t.Fatalf("root_actions 共 %d 条，超过内核协议上限 %d 条（会导致 store/install 拒绝安装）",
			len(info.RootActions), maxRootActions)
	}
	byID := map[string]pluginapi.RootAction{}
	for _, a := range info.RootActions {
		if err := pluginapi.ValidateRootAction(a); err != nil {
			t.Errorf("%s schema: %v", a.ID, err)
		}
		if _, dup := byID[a.ID]; dup {
			t.Errorf("%s 重复", a.ID)
		}
		byID[a.ID] = a
		// 声明 argv 本身也要过受控形状表（语句级白名单 + ≤8 句）。
		if err := pluginapi.ValidateRootAppendedArgv(a.Argv, nil); err != nil {
			t.Errorf("%s 声明 argv: %v", a.ID, err)
		}
	}
	// IP 名单的动作必须齐（多一条就超上限，少一条功能就断）。
	for _, id := range []string{"nft-list", "nft-init", "nft-add-allow4", "nft-del-allow4",
		"nft-add-deny4", "nft-del-deny4"} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("缺少 root_action %s", id)
		}
	}
	// 追加参数形状：{ <ip> }、{ <ip> timeout Ns }、{ <ip> <v6> } 都要能拼成一条语句。
	samples := []struct {
		id   string
		args []string
	}{
		{"nft-add-allow4", []string{"{", "203.0.113.7", "}"}},
		{"nft-add-deny4", []string{"{", "10.0.0.0/8", "}"}},
		{"nft-add-deny4", []string{"{", "203.0.113.7", "timeout", "600s", "}"}},
		{"nft-del-allow4", []string{"{", "203.0.113.7", "}"}},
		{"nft-del-deny4", []string{"{", "10.0.0.0/8", "}"}},
	}
	for _, s := range samples {
		if err := pluginapi.ValidateRootAppendedArgv(byID[s.id].Argv, s.args); err != nil {
			t.Errorf("%s 追加参数 %v: %v", s.id, s.args, err)
		}
	}
	// 注入形状必须被拒：追加参数不能拼出第二条语句（";" 不在任何 Tail 形状里）。
	if err := pluginapi.ValidateRootAppendedArgv(byID["nft-add-deny4"].Argv,
		[]string{"{", "1.2.3.4", "}", ";", "add", "table", "inet", "kore_evil"}); err == nil {
		t.Error("追加参数里带 \";\" 应被形状表拒绝")
	}
}
