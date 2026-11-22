// Package fwop 实现 firewall 插件的方法面：探测真实防火墙后端（ufw / iptables）、
// 读取规则、以及仅针对 ufw 的规则写操作。
//
// 边界：只调用固定 argv 的外部命令（ufw / iptables），不拼接 shell、不读写宿主
// 配置文件、不启用/禁用防火墙；写操作统一带 SSH 保护与 dry-run，缺省不执行。
package fwop

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// 后端、动作、方向与协议常量。
const (
	BackendUFW      = "ufw"
	BackendIptables = "iptables"
	BackendNone     = "none"

	ActionAllow  = "allow"
	ActionDeny   = "deny"
	ActionReject = "reject"

	DirectionIn  = "in"
	DirectionOut = "out"

	ProtoTCP = "tcp"
	ProtoUDP = "udp"
	ProtoAny = "any"
)

// 安全边界常量。
const (
	// CapabilityAdmin 是写操作要求的能力（与 info.json 声明一致）。
	CapabilityAdmin = "system:admin"
	// DefaultSSHPort 是 SSH 默认端口；即使配置了 KORE_SSH_PORT 也始终受保护。
	DefaultSSHPort = 22
	// maxCommentRunes 是规则注释的最大字符数。
	maxCommentRunes = 64
)

// StatusResult 是 firewall.status 的结果。
//
// 语义约定：
//   - backend：按 ufw > iptables > none 的优先级探测到的后端；
//   - available：后端存在且状态探测成功（非 root 时通常为 false，error 说明原因）；
//   - enabled / default_in / rules_count：仅在 available=true 时可信；
//   - error：探测失败原因（空串表示成功）。status 不因探测失败返回协议错误。
type StatusResult struct {
	Backend    string `json:"backend"`
	Available  bool   `json:"available"`
	Enabled    bool   `json:"enabled"`
	DefaultIn  string `json:"default_in"`
	RulesCount int    `json:"rules_count"`
	Error      string `json:"error"`
	// ErrorCode 是机器可读错误码（ADR-0018：非 root 时为 E_NEED_ROOT），
	// 仅 available=false 时出现；UI 据此禁用并展示可操作提示，不渲染成"无数据"。
	ErrorCode string `json:"error_code,omitempty"`
	// Hint 是"下一步怎么做"的中文提示（如提权通道的 action id）。
	Hint string `json:"hint,omitempty"`
}

// Rule 是一条统一结构的防火墙规则。
//
// Index 是 ufw 编号（iptables 为 INPUT 链内 1-based 序号）；WriteResult.Rule
// 中新建规则 Index=0（ufw 编号在执行后才确定）。
type Rule struct {
	Index     int       `json:"index"`
	Action    string    `json:"action"`
	Direction string    `json:"direction"`
	Proto     string    `json:"proto"`
	Port      PortValue `json:"port"`
	From      string    `json:"from"`
	Comment   string    `json:"comment"`
}

// Describe 返回规则的可读摘要，用于安全护栏错误信息。
func (r Rule) Describe() string {
	port := string(r.Port)
	if port == "" {
		port = "any"
	}
	from := r.From
	if from == "" {
		from = "0.0.0.0/0"
	}
	return fmt.Sprintf("%s %s %s/%s from %s", r.Action, r.Direction, r.Proto, port, from)
}

// RulesResult 是 firewall.rules 的结果。
type RulesResult struct {
	Backend string `json:"backend"`
	Rules   []Rule `json:"rules"`
	Count   int    `json:"count"`
}

// WriteResult 是 allowPort / denyPort 的结果。
// dry_run=true 时 Applied 恒为 false，Command 是「本应执行」的命令。
type WriteResult struct {
	Applied bool     `json:"applied"`
	DryRun  bool     `json:"dry_run"`
	Backend string   `json:"backend"`
	Command []string `json:"command"`
	Rule    Rule     `json:"rule"`
}

// DeleteResult 是 deleteRule 的结果。
type DeleteResult struct {
	Applied bool     `json:"applied"`
	DryRun  bool     `json:"dry_run"`
	Backend string   `json:"backend"`
	Command []string `json:"command"`
	Deleted Rule     `json:"deleted"`
}

// 方法入参形状：对外 schema 全部显式定形，不用 map[string]any。
type (
	rulesParams struct {
		Backend string `json:"backend,omitempty"`
	}

	allowPortParams struct {
		Port    int    `json:"port"`
		Proto   string `json:"proto,omitempty"`
		From    string `json:"from,omitempty"`
		Comment string `json:"comment,omitempty"`
		DryRun  bool   `json:"dry_run,omitempty"`
	}

	denyPortParams struct {
		Port   int    `json:"port"`
		Proto  string `json:"proto,omitempty"`
		From   string `json:"from,omitempty"`
		DryRun bool   `json:"dry_run,omitempty"`
	}

	deleteRuleParams struct {
		Index  int  `json:"index"`
		DryRun bool `json:"dry_run,omitempty"`
	}
)

// PortValue 是规则端口：单端口按 JSON 数字输出，区间/多端口/空值按字符串输出。
// 这样既满足 `port:22|"22:80"|""` 的约定，又避免把端口当 any 逃逸。
type PortValue string

// MarshalJSON 实现按形状输出：仅规范十进制单端口写成数字。
func (p PortValue) MarshalJSON() ([]byte, error) {
	s := string(p)
	if s == "" {
		return []byte(`""`), nil
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && strconv.Itoa(n) == s {
		return []byte(s), nil
	}
	return []byte(strconv.Quote(s)), nil
}

// UnmarshalJSON 接受数字或字符串两种写法（测试与回读均可用）。
func (p *PortValue) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))
	if text == "" || text == "null" {
		*p = ""
		return nil
	}
	if strings.HasPrefix(text, `"`) {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*p = PortValue(s)
		return nil
	}
	if _, err := strconv.Atoi(text); err != nil {
		return fmt.Errorf("port 必须是数字或字符串: %s", text)
	}
	*p = PortValue(text)
	return nil
}

// Covers 判断端口是否覆盖给定端口：空值表示全端口；支持单端口、a:b 区间、逗号列表。
func (p PortValue) Covers(port int) bool {
	raw := strings.TrimSpace(string(p))
	if raw == "" {
		return true
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := splitPortRange(part); ok {
			if port >= lo && port <= hi {
				return true
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil && n == port {
			return true
		}
	}
	return false
}

// splitPortRange 解析 "a:b" 形式的端口区间（ufw / iptables 同一写法）。
func splitPortRange(text string) (int, int, bool) {
	loText, hiText, ok := strings.Cut(text, ":")
	if !ok {
		return 0, 0, false
	}
	lo, err := strconv.Atoi(strings.TrimSpace(loText))
	if err != nil {
		return 0, 0, false
	}
	hi, err := strconv.Atoi(strings.TrimSpace(hiText))
	if err != nil || hi < lo {
		return 0, 0, false
	}
	return lo, hi, true
}
