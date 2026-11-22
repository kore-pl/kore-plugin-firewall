package fwop

import "testing"

// TestParseIptablesS 只读 INPUT 链：默认策略、动作、协议、端口、来源解析。
func TestParseIptablesS(t *testing.T) {
	parsed := parseIptablesS(iptablesSFixture)
	if parsed.defaultIn != "deny" {
		t.Fatalf("default_in=%q，期望 deny", parsed.defaultIn)
	}
	if len(parsed.rules) != 6 {
		t.Fatalf("解析出 %d 条规则，期望 6（跳过 DOCKER-USER 跳转）: %+v", len(parsed.rules), parsed.rules)
	}

	expected := []Rule{
		{Index: 1, Action: ActionAllow, Direction: DirectionIn, Proto: ProtoAny, Port: "", From: "0.0.0.0/0", Comment: "[iface=lo]"},
		{Index: 2, Action: ActionAllow, Direction: DirectionIn, Proto: ProtoTCP, Port: "22", From: "0.0.0.0/0"},
		{Index: 3, Action: ActionAllow, Direction: DirectionIn, Proto: ProtoUDP, Port: "53", From: "10.0.0.0/8"},
		{Index: 4, Action: ActionAllow, Direction: DirectionIn, Proto: ProtoTCP, Port: "80,443", From: "0.0.0.0/0"},
		{Index: 5, Action: ActionDeny, Direction: DirectionIn, Proto: ProtoTCP, Port: "3306", From: "0.0.0.0/0"},
		{Index: 6, Action: ActionReject, Direction: DirectionIn, Proto: ProtoAny, Port: "", From: "0.0.0.0/0"},
	}
	for i, want := range expected {
		got := parsed.rules[i]
		if got != want {
			t.Fatalf("第 %d 条规则=%+v，期望 %+v", i+1, got, want)
		}
	}
}

// TestParseIptablesSPolicies INPUT 默认策略三种映射。
func TestParseIptablesSPolicies(t *testing.T) {
	cases := map[string]string{
		"-P INPUT ACCEPT": "accept",
		"-P INPUT DROP":   "deny",
		"-P INPUT REJECT": "reject",
		"-P INPUT foo":    "",
	}
	for line, want := range cases {
		if got := parseIptablesS(line + "\n").defaultIn; got != want {
			t.Fatalf("%q 解析为 %q，期望 %q", line, got, want)
		}
	}
}

// TestParseIptablesSIcmp 非 TCP/UDP 协议保留真实协议名，不伪装成 any。
func TestParseIptablesSIcmp(t *testing.T) {
	parsed := parseIptablesS("-A INPUT -p icmp -j ACCEPT\n")
	if len(parsed.rules) != 1 || parsed.rules[0].Proto != "icmp" {
		t.Fatalf("icmp 规则解析不符: %+v", parsed.rules)
	}
}
