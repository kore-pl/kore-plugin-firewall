package fwop

import (
	"regexp"
	"strconv"
	"strings"
)

// ufwStatus 是 `ufw status` 的解析结果。
type ufwStatus struct {
	enabled   bool
	defaultIn string
	rules     []Rule // 仅 `status numbered` 填充
	count     int
}

var (
	// ufwNumberedLine 匹配 `[ 1] 22/tcp ALLOW IN Anywhere` 的编号前缀。
	ufwNumberedLine = regexp.MustCompile(`^\[\s*(\d+)\]\s+(.*)$`)
	// ufwRuleBody 把 "To  ACTION DIR  From" 拆成三段；To 不含动作关键字，故非贪婪即可。
	ufwRuleBody = regexp.MustCompile(`^(.*?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s+(.*)$`)
)

// parseUfwStatusVerbose 解析 `ufw status verbose`：状态、默认入站策略与规则条数。
// 规则表格从分隔行（`--  ------  ----`）之后开始；每个非空行算一条（含 v6 条目）。
func parseUfwStatusVerbose(output string) ufwStatus {
	status := ufwStatus{}
	inTable := false
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		switch {
		case strings.HasPrefix(line, "Status:"):
			status.enabled = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "Status:")), "active")
		case strings.HasPrefix(line, "Default:"):
			status.defaultIn = parseUfwDefaultIn(line)
		case strings.HasPrefix(line, "--"):
			inTable = true
		case inTable && line != "":
			status.count++
		}
	}
	return status
}

// parseUfwDefaultIn 从 "Default: deny (incoming), allow (outgoing), ..." 取入站策略。
func parseUfwDefaultIn(line string) string {
	value := strings.TrimSpace(strings.TrimPrefix(line, "Default:"))
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, "(incoming)") {
			continue
		}
		policy := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(part, "(incoming)")))
		switch policy {
		case "allow":
			return "accept"
		case "deny":
			return "deny"
		case "reject":
			return "reject"
		}
	}
	return ""
}

// parseUfwStatusNumbered 解析 `ufw status numbered`：编号 + 统一规则结构。
// 解析失败的行直接跳过（例如警告文本），不伪造规则。
func parseUfwStatusNumbered(output string) ufwStatus {
	status := ufwStatus{}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if strings.HasPrefix(line, "Status:") {
			status.enabled = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "Status:")), "active")
			continue
		}
		if strings.HasPrefix(line, "Default:") {
			status.defaultIn = parseUfwDefaultIn(line)
			continue
		}
		match := ufwNumberedLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		index, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		rule, ok := parseUfwRuleBody(index, match[2])
		if !ok {
			continue
		}
		status.rules = append(status.rules, rule)
	}
	status.count = len(status.rules)
	return status
}

// parseUfwRuleBody 解析编号行主体并归一为统一规则结构。
func parseUfwRuleBody(index int, body string) (Rule, bool) {
	match := ufwRuleBody.FindStringSubmatch(strings.TrimSpace(body))
	if match == nil {
		return Rule{}, false
	}
	to := match[1]
	action := mapUfwAction(match[2])
	direction := mapUfwDirection(match[3])
	tail := match[4]

	comment := ""
	if hash := strings.Index(tail, "#"); hash >= 0 {
		comment = strings.TrimSpace(tail[hash+1:])
		tail = strings.TrimSpace(tail[:hash])
	}
	port, proto, iface, toAddress := parseUfwTo(to)
	from := parseUfwFrom(tail)

	annotations := make([]string, 0, 2)
	if iface != "" {
		annotations = append(annotations, "iface="+iface)
	}
	if toAddress != "" {
		annotations = append(annotations, "to="+toAddress)
	}
	if len(annotations) > 0 {
		comment = strings.TrimSpace(comment + " [" + strings.Join(annotations, ",") + "]")
	}
	return Rule{
		Index:     index,
		Action:    action,
		Direction: direction,
		Proto:     proto,
		Port:      port,
		From:      from,
		Comment:   comment,
	}, true
}

// mapUfwAction 归一动作：ufw 的 LIMIT 是限速放行，归为 allow。
func mapUfwAction(raw string) string {
	switch strings.ToUpper(raw) {
	case "ALLOW", "LIMIT":
		return ActionAllow
	case "DENY":
		return ActionDeny
	case "REJECT":
		return ActionReject
	}
	return ActionAllow
}

// mapUfwDirection 归一方向：FWD（转发）按入站侧处理，保证 SSH 护栏目不漏判。
func mapUfwDirection(raw string) string {
	if strings.EqualFold(raw, "OUT") {
		return DirectionOut
	}
	return DirectionIn
}

// parseUfwTo 解析 To 列：端口 / 协议 / 接口限定 / 目的地址限定。
// 返回的 toAddress 非空表示该规则限定了目的地址，统一结构无法表达，由调用方注解到 comment。
func parseUfwTo(raw string) (port PortValue, proto, iface, toAddress string) {
	value := strings.TrimSpace(raw)
	if idx := strings.Index(value, " on "); idx >= 0 {
		iface = strings.TrimSpace(value[idx+4:])
		value = strings.TrimSpace(value[:idx])
	}
	value = strings.TrimSpace(strings.TrimSuffix(value, "(v6)"))
	if value == "" || strings.EqualFold(value, "anywhere") || strings.EqualFold(value, "any") {
		return "", ProtoAny, iface, ""
	}
	if idx := strings.LastIndex(value, "/"); idx >= 0 {
		head := strings.TrimSpace(value[:idx])
		tail := strings.ToLower(strings.TrimSpace(value[idx+1:]))
		if isPortList(head) && isProtoName(tail) {
			return PortValue(head), tail, iface, ""
		}
	}
	if isPortList(value) {
		return PortValue(value), ProtoAny, iface, ""
	}
	return "", ProtoAny, iface, value
}

// parseUfwFrom 解析 From 列：Anywhere / Anywhere (v6) / IP / CIDR。
func parseUfwFrom(raw string) string {
	value := strings.TrimSpace(raw)
	isV6 := strings.Contains(value, "(v6)")
	value = strings.TrimSpace(strings.TrimSuffix(value, "(v6)"))
	if idx := strings.Index(value, " on "); idx >= 0 {
		value = strings.TrimSpace(value[:idx])
	}
	if value == "" || strings.EqualFold(value, "anywhere") || strings.EqualFold(value, "any") {
		if isV6 {
			return "::/0"
		}
		return "0.0.0.0/0"
	}
	return value
}

// isPortList 判断片段是否是端口表达式（单端口/区间/逗号列表）。
func isPortList(text string) bool {
	if text == "" {
		return false
	}
	for _, r := range text {
		if (r >= '0' && r <= '9') || r == ',' || r == ':' {
			continue
		}
		return false
	}
	return true
}

// isProtoName 判断片段是否是协议名（字母/数字）。
func isProtoName(text string) bool {
	if text == "" {
		return false
	}
	for _, r := range text {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

// buildUfwRuleCommand 构造放行/拒绝命令。argv 固定、参数逐个成项，不经过 shell。
// 命令形态：ufw allow|deny proto tcp from <from> to any port <N> [comment <text>]
func buildUfwRuleCommand(path, action string, port int, proto, from, comment string) []string {
	argv := []string{
		path, action,
		"proto", proto,
		"from", from,
		"to", "any",
		"port", strconv.Itoa(port),
	}
	if comment != "" {
		argv = append(argv, "comment", comment)
	}
	return argv
}

// buildUfwDeleteCommand 构造按编号删除命令：ufw --force delete <index>。
func buildUfwDeleteCommand(path string, index int) []string {
	return []string{path, "--force", "delete", strconv.Itoa(index)}
}
