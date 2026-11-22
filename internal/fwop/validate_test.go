package fwop

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestValidatePort 端口只接受 1-65535 的整数边界。
func TestValidatePort(t *testing.T) {
	for _, port := range []int{1, 22, 65535} {
		if perr := validatePort(port); perr != nil {
			t.Fatalf("port=%d 应合法，实际错误: %v", port, perr)
		}
	}
	for _, port := range []int{0, -1, 65536, 100000} {
		perr := validatePort(port)
		if perr == nil || perr.Code != "E_INVALID" {
			t.Fatalf("port=%d 应返回 E_INVALID，实际: %+v", port, perr)
		}
	}
}

// TestNormalizeProto 协议缺省 tcp，只接受 tcp/udp（大小写不敏感）。
func TestNormalizeProto(t *testing.T) {
	cases := map[string]string{"": "tcp", "tcp": "tcp", "UDP": "udp", " udp ": "udp"}
	for raw, want := range cases {
		got, perr := normalizeProto(raw)
		if perr != nil {
			t.Fatalf("proto=%q 应合法，实际错误: %v", raw, perr)
		}
		if got != want {
			t.Fatalf("proto=%q 归一为 %q，期望 %q", raw, got, want)
		}
	}
	for _, raw := range []string{"icmp", "sctp", "tcp,udp", "tcp;rm"} {
		if _, perr := normalizeProto(raw); perr == nil || perr.Code != "E_INVALID" {
			t.Fatalf("proto=%q 应返回 E_INVALID，实际: %+v", raw, perr)
		}
	}
}

// TestNormalizeFrom 来源只接受 any 或合法 IP/CIDR，拒绝主机名与注入字符。
func TestNormalizeFrom(t *testing.T) {
	valid := map[string]string{
		"":                 "any",
		"any":              "any",
		"ANY":              "any",
		"192.0.2.10":       "192.0.2.10",
		"10.0.0.0/8":       "10.0.0.0/8",
		"2001:db8::1":      "2001:db8::1",
		"2001:db8::/32":    "2001:db8::/32",
		" 198.51.100.0/24": "198.51.100.0/24",
	}
	for raw, want := range valid {
		got, perr := normalizeFrom(raw)
		if perr != nil {
			t.Fatalf("from=%q 应合法，实际错误: %v", raw, perr)
		}
		if got != want {
			t.Fatalf("from=%q 归一为 %q，期望 %q", raw, got, want)
		}
	}
	invalid := []string{
		"example.com",
		"1.2.3.4 5.6.7.8",
		"0.0.0.0/33",
		"999.1.1.1",
		"1.2.3.4; rm -rf /",
		"1.2.3.4|cat /etc/passwd",
		"$(id)",
		"1.2.3.4\n5.6.7.8",
	}
	for _, raw := range invalid {
		if _, perr := normalizeFrom(raw); perr == nil || perr.Code != "E_INVALID" {
			t.Fatalf("from=%q 应返回 E_INVALID，实际: %+v", raw, perr)
		}
	}
}

// TestValidateComment 注释长度与字符白名单。
func TestValidateComment(t *testing.T) {
	if perr := validateComment(""); perr != nil {
		t.Fatalf("空注释应合法: %v", perr)
	}
	if perr := validateComment("kore web 80 (nginx) #1"); perr != nil {
		t.Fatalf("常规注释应合法: %v", perr)
	}
	if perr := validateComment(strings.Repeat("a", 64)); perr != nil {
		t.Fatalf("64 字符注释应合法: %v", perr)
	}
	if perr := validateComment(strings.Repeat("a", 65)); perr == nil {
		t.Fatal("65 字符注释应被拒绝")
	}
	for _, raw := range []string{"a\nb", "a\"b", "a'b", "a*b", "a\\b"} {
		if perr := validateComment(raw); perr == nil {
			t.Fatalf("注释 %q 应被拒绝", raw)
		}
	}
}

// TestParseSSHPorts KORE_SSH_PORT 解析：始终含 22、去重、非法值报错。
func TestParseSSHPorts(t *testing.T) {
	ports, err := ParseSSHPorts("")
	if err != nil || len(ports) != 1 || ports[0] != 22 {
		t.Fatalf("空配置应只含 22: ports=%v err=%v", ports, err)
	}
	ports, err = ParseSSHPorts("2222, 22,2222")
	if err != nil {
		t.Fatalf("合法配置报错: %v", err)
	}
	if len(ports) != 2 || ports[0] != 22 || ports[1] != 2222 {
		t.Fatalf("去重结果不符: %v", ports)
	}
	for _, raw := range []string{"abc", "0", "65536", "22,", "22,,2222"} {
		if _, err := ParseSSHPorts(raw); err == nil {
			t.Fatalf("KORE_SSH_PORT=%q 应报错", raw)
		}
	}
}

// TestPortValueJSON 单端口输出数字，区间/多端口输出字符串，空值输出空串。
func TestPortValueJSON(t *testing.T) {
	cases := map[PortValue]string{
		"22":     `22`,
		"":       `""`,
		"22:80":  `"22:80"`,
		"80,443": `"80,443"`,
		"022":    `"022"`,
	}
	for port, want := range cases {
		data, err := json.Marshal(port)
		if err != nil {
			t.Fatalf("序列化 %q 失败: %v", port, err)
		}
		if string(data) != want {
			t.Fatalf("port=%q 序列化为 %s，期望 %s", port, data, want)
		}
	}
}

// TestPortValueCovers SSH 护栏目依赖的端口覆盖判断。
func TestPortValueCovers(t *testing.T) {
	cases := []struct {
		port  PortValue
		check int
		want  bool
	}{
		{"", 22, true},
		{"22", 22, true},
		{"22", 2222, false},
		{"22:80", 22, true},
		{"22:80", 80, true},
		{"22:80", 81, false},
		{"80,443", 443, true},
		{"80,443", 22, false},
	}
	for _, c := range cases {
		if got := c.port.Covers(c.check); got != c.want {
			t.Fatalf("port=%q Covers(%d)=%v，期望 %v", c.port, c.check, got, c.want)
		}
	}
}
