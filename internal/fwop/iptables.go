package fwop

import (
	"strings"
)

// iptablesRuleset 是 `iptables -S` 的解析结果（只取 INPUT 链与 INPUT 默认策略）。
type iptablesRuleset struct {
	defaultIn string
	rules     []Rule
}

// parseIptablesS 解析 `iptables -S`：只读 INPUT 链，跳过其它链与自定义链跳转。
//
// 约定：
//   - `-P INPUT DROP` → default_in=deny（ACCEPT→accept / REJECT→reject）；
//   - 动作只认 ACCEPT / DROP / REJECT 三个终止目标；跳转自定义链（如 DOCKER-USER）
//     无法归一到 allow/deny/reject，跳过并在 README 说明；
//   - Index 是该行在 INPUT 链内的 1-based 位置（跳过的行也占位，便于定位）。
func parseIptablesS(output string) iptablesRuleset {
	var result iptablesRuleset
	position := 0
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if strings.HasPrefix(line, "-P INPUT ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				result.defaultIn = mapIptablesPolicy(fields[2])
			}
			continue
		}
		if !strings.HasPrefix(line, "-A INPUT ") {
			continue
		}
		position++
		fields := strings.Fields(line)
		action, ok := mapIptablesTarget(argValue(fields, "-j", "--jump"))
		if !ok {
			continue
		}
		proto := strings.ToLower(argValue(fields, "-p", "--protocol"))
		if proto == "" || proto == "all" {
			proto = ProtoAny
		}
		port := argValue(fields, "--dport", "--dports", "--destination-port")
		from := argValue(fields, "-s", "--source")
		if from == "" {
			from = "0.0.0.0/0"
		}
		comment := strings.Trim(argValue(fields, "--comment"), `"`)
		if iface := argValue(fields, "-i", "--in-interface"); iface != "" {
			comment = strings.TrimSpace(comment + " [iface=" + iface + "]")
		}
		result.rules = append(result.rules, Rule{
			Index:     position,
			Action:    action,
			Direction: DirectionIn,
			Proto:     proto,
			Port:      PortValue(port),
			From:      from,
			Comment:   comment,
		})
	}
	return result
}

// mapIptablesPolicy 把 INPUT 链默认策略映射为统一默认值。
func mapIptablesPolicy(raw string) string {
	switch strings.ToUpper(raw) {
	case "ACCEPT":
		return "accept"
	case "DROP":
		return "deny"
	case "REJECT":
		return "reject"
	}
	return ""
}

// mapIptablesTarget 把 -j 目标映射为统一动作；非终止目标返回 false。
func mapIptablesTarget(raw string) (string, bool) {
	switch strings.ToUpper(raw) {
	case "ACCEPT":
		return ActionAllow, true
	case "DROP":
		return ActionDeny, true
	case "REJECT":
		return ActionReject, true
	}
	return "", false
}

// argValue 返回第一个命中的参数名后面的值；未命中返回空串。
func argValue(fields []string, names ...string) string {
	for i := 0; i+1 < len(fields); i++ {
		for _, name := range names {
			if fields[i] == name {
				return fields[i+1]
			}
		}
	}
	return ""
}
