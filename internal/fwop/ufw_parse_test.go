package fwop

import (
	"strings"
	"testing"
)

// TestParseUfwStatusVerbose 状态/默认入站策略/规则条数解析。
func TestParseUfwStatusVerbose(t *testing.T) {
	status := parseUfwStatusVerbose(ufwVerboseActive)
	if !status.enabled {
		t.Fatal("active 状态解析为未启用")
	}
	if status.defaultIn != "deny" {
		t.Fatalf("default_in=%q，期望 deny", status.defaultIn)
	}
	if status.count != 5 {
		t.Fatalf("rules_count=%d，期望 5", status.count)
	}

	inactive := parseUfwStatusVerbose(ufwVerboseInactive)
	if inactive.enabled {
		t.Fatal("inactive 状态解析为已启用")
	}
	if inactive.count != 0 {
		t.Fatalf("inactive 规则数=%d，期望 0", inactive.count)
	}
	if inactive.defaultIn != "" {
		t.Fatalf("inactive 不应编造 default_in，实际 %q", inactive.defaultIn)
	}
}

// TestParseUfwStatusVerboseDefaultPolicies 默认入站策略三种取值映射。
func TestParseUfwStatusVerboseDefaultPolicies(t *testing.T) {
	cases := map[string]string{
		"Default: allow (incoming), allow (outgoing), disabled (routed)": "accept",
		"Default: deny (incoming), allow (outgoing), disabled (routed)":  "deny",
		"Default: reject (incoming), allow (outgoing), deny (routed)":    "reject",
		"Default: deny (outgoing), allow (outgoing), deny (routed)":      "",
	}
	for line, want := range cases {
		if got := parseUfwDefaultIn(line); got != want {
			t.Fatalf("%q 解析为 %q，期望 %q", line, got, want)
		}
	}
}

// TestParseUfwNumbered 编号规则解析：动作/方向/协议/端口/来源/注释全部归一。
func TestParseUfwNumbered(t *testing.T) {
	status := parseUfwStatusNumbered(ufwNumberedFixture)
	if !status.enabled {
		t.Fatal("编号输出应解析为 active")
	}
	if len(status.rules) != 7 {
		t.Fatalf("解析出 %d 条规则，期望 7: %+v", len(status.rules), status.rules)
	}
	byIndex := make(map[int]Rule, len(status.rules))
	for _, rule := range status.rules {
		byIndex[rule.Index] = rule
	}

	cases := []struct {
		index   int
		action  string
		proto   string
		port    PortValue
		from    string
		comment string
	}{
		{1, ActionAllow, ProtoTCP, "22", "0.0.0.0/0", "ssh"},
		{2, ActionAllow, ProtoTCP, "80,443", "0.0.0.0/0", ""},
		{3, ActionDeny, ProtoTCP, "8080:8090", "10.0.0.0/8", ""},
		{4, ActionReject, ProtoAny, "", "203.0.113.7", ""},
		{5, ActionAllow, ProtoTCP, "22", "::/0", "ssh"},
		{6, ActionAllow, ProtoTCP, "22", "0.0.0.0/0", "[iface=eth0]"},
		{7, ActionAllow, ProtoUDP, "53", "0.0.0.0/0", "dns rate"},
	}
	for _, c := range cases {
		rule, ok := byIndex[c.index]
		if !ok {
			t.Fatalf("缺少编号 %d", c.index)
		}
		if rule.Action != c.action || rule.Proto != c.proto || rule.Port != c.port || rule.From != c.from || rule.Comment != c.comment {
			t.Fatalf("[%d] 解析=%+v，期望 action=%s proto=%s port=%q from=%s comment=%q",
				c.index, rule, c.action, c.proto, c.port, c.from, c.comment)
		}
		if rule.Direction != DirectionIn {
			t.Fatalf("[%d] direction=%s，期望 in", c.index, rule.Direction)
		}
	}
}

// TestParseUfwNumberedInactive inactive 时不应产生规则。
func TestParseUfwNumberedInactive(t *testing.T) {
	status := parseUfwStatusNumbered("Status: inactive\n")
	if status.enabled || len(status.rules) != 0 {
		t.Fatalf("inactive 解析结果不符: %+v", status)
	}
}

// TestParseUfwRuleBodyEdgeCases 目的地址限定/无法解析的行按约定处理。
func TestParseUfwRuleBodyEdgeCases(t *testing.T) {
	rule, ok := parseUfwRuleBody(9, "10.0.0.5 80/tcp   ALLOW IN    Anywhere")
	if !ok {
		t.Fatal("带目的地址的规则应可解析")
	}
	if string(rule.Port) != "" || !strings.Contains(rule.Comment, "to=10.0.0.5 80") {
		t.Fatalf("目的地址限定应注解到 comment 且不编造端口: %+v", rule)
	}
	if _, ok := parseUfwRuleBody(10, "garbage line"); ok {
		t.Fatal("无法解析的行应返回 false")
	}
}
