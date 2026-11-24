package fwop

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// validatePort 校验端口在 1-65535 区间。
func validatePort(port int) *pluginapi.Error {
	if port < 1 || port > 65535 {
		return invalid(fmt.Sprintf("port 必须在 1-65535 之间（收到 %d）", port))
	}
	return nil
}

// normalizeProto 归一协议：缺省 tcp，只接受 tcp/udp（大小写不敏感）。
// 写操作不做 icmp：端口语义对 icmp 不成立。
func normalizeProto(raw string) (string, *pluginapi.Error) {
	proto := strings.ToLower(strings.TrimSpace(raw))
	switch proto {
	case "":
		return ProtoTCP, nil
	case ProtoTCP, ProtoUDP:
		return proto, nil
	}
	return "", invalid("proto 必须是 tcp/udp（缺省 tcp）")
}

// normalizeFrom 归一来源：缺省 any；显式值只能是 any 或合法 IP / CIDR。
// 用 net.ParseIP / net.ParseCIDR 做白名单校验，比正则更严格，杜绝命令注入面。
func normalizeFrom(raw string) (string, *pluginapi.Error) {
	from := strings.TrimSpace(raw)
	if from == "" || strings.EqualFold(from, ProtoAny) {
		return ProtoAny, nil
	}
	if strings.ContainsAny(from, " \t\r\n\"'`;|&$><(){}[]*?!\\") {
		return "", invalid("from 只接受 IP/CIDR 或 any（含非法字符）")
	}
	if strings.Contains(from, "/") {
		if _, _, err := net.ParseCIDR(from); err != nil {
			return "", invalid("from 不是合法的 CIDR: " + from)
		}
		return from, nil
	}
	if net.ParseIP(from) == nil {
		return "", invalid("from 只接受 IP/CIDR 或 any: " + from)
	}
	return from, nil
}

// validateComment 校验 ufw 规则注释：≤64 字符，允许字母（含中文）/数字/有限标点。
func validateComment(raw string) *pluginapi.Error {
	comment := strings.TrimSpace(raw)
	if comment == "" {
		return nil
	}
	if utf8.RuneCountInString(comment) > maxCommentRunes {
		return invalid(fmt.Sprintf("comment 最多 %d 个字符", maxCommentRunes))
	}
	for _, r := range comment {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		switch r {
		case ' ', '.', '_', ':', '/', '@', '-', '#', '(', ')':
			continue
		}
		return invalid("comment 只允许字母/数字/空格与 ._:/@-#()")
	}
	return nil
}

// ParseSSHPorts 解析 KORE_SSH_PORT（可为逗号分隔的多个端口），并始终并入 22。
// 非法取值直接返回错误，由启动流程失败退出——不静默退回默认值。
func ParseSSHPorts(raw string) ([]int, error) {
	ports := []int{DefaultSSHPort}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ports, nil
	}
	for _, part := range strings.Split(trimmed, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			return nil, fmt.Errorf("KORE_SSH_PORT=%q 含空项", raw)
		}
		port, err := strconv.Atoi(item)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("KORE_SSH_PORT=%q 非法：每个端口必须是 1-65535 的整数", item)
		}
		ports = append(ports, port)
	}
	return dedupePorts(ports), nil
}

// normalizeSSHPorts 校验并去重保护端口集合，并强制包含 22。
func normalizeSSHPorts(raw []int) ([]int, error) {
	ports := []int{DefaultSSHPort}
	for _, port := range raw {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("SSH 保护端口 %d 非法：必须是 1-65535", port)
		}
		ports = append(ports, port)
	}
	return dedupePorts(ports), nil
}

// dedupePorts 去重并保持首次出现顺序。
func dedupePorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	result := make([]int, 0, len(ports))
	for _, port := range ports {
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		result = append(result, port)
	}
	return result
}

// checkDenySSHPort 是 denyPort 的 SSH 保护：目标是 22 或任一配置的 SSH 端口即拒绝。
// 在构造命令与执行之前完成，dry_run 同样被拒。
func (r *Runtime) checkDenySSHPort(port int) *pluginapi.Error {
	for _, sshPort := range r.settings.sshPorts() {
		if port != sshPort {
			continue
		}
		if sshPort == DefaultSSHPort {
			return unauthorized("拒绝屏蔽 SSH 端口 22：这会导致你无法再连接到服务器。如确实需要，请先确认有其他登录方式")
		}
		return unauthorized(fmt.Sprintf("拒绝屏蔽 SSH 端口 %d（KORE_SSH_PORT 配置）：这会导致你无法再连接到服务器。如确实需要，请先确认有其他登录方式", sshPort))
	}
	return nil
}

// checkDeleteSSHAllow 是 deleteRule 的 SSH 保护：只拦截「入站 + allow + 覆盖 SSH 端口」
// 的规则删除，删除 deny / out 规则不受影响。
func (r *Runtime) checkDeleteSSHAllow(rule Rule) *pluginapi.Error {
	if rule.Action != ActionAllow || rule.Direction != DirectionIn {
		return nil
	}
	for _, sshPort := range r.settings.sshPorts() {
		if !rule.Port.Covers(sshPort) {
			continue
		}
		return unauthorized(fmt.Sprintf(
			"拒绝删除 SSH 放行规则 [%d]（%s）：删除后可能无法再连接到服务器。如确实需要，请先确认有其他登录方式",
			rule.Index, rule.Describe(),
		))
	}
	return nil
}
