// Package fwop 实现 firewall 插件的方法面：参数校验、协议收口与结构化结果。
// 本包只做逻辑校验与执行面调用，不调用 iptables/nftables/firewalld（骨架口径）。
package fwop

import "fmt"

// maxRules 是骨架口径下 firewall.rules 返回的最大条目数。
const maxRules = 1024

// FaultKind 标识一次故障注入的类别。
type FaultKind string

const (
	FaultNone    FaultKind = ""
	FaultKill    FaultKind = "kill"
	FaultTimeout FaultKind = "timeout"
	FaultDisk    FaultKind = "disk"
	FaultCgroup  FaultKind = "cgroup"
)

// FaultError 是执行面注入的故障错误，Call 将其映射为协议错误码。
type FaultError struct {
	Kind    FaultKind
	Message string
}

// Error 实现 error 接口，输出 "<类别>: <说明>"。
func (e *FaultError) Error() string { return fmt.Sprintf("%s: %s", e.Kind, e.Message) }

// NewFaultError 构造给定类别的故障错误。
func NewFaultError(kind FaultKind, message string) *FaultError {
	return &FaultError{Kind: kind, Message: message}
}

// Rule 是一条逻辑防火墙规则（骨架口径，不对应真实链）。
type Rule struct {
	ID       string `json:"id"`
	Action   string `json:"action"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Scope    string `json:"scope"`
}

// Executor 是防火墙操作的执行面；骨架实现为 noop，测试可注入故障执行器。
type Executor interface {
	Rules(action, chain string) ([]Rule, error)
	AllowPort(port int, protocol string) (bool, error)
}

// rulesParams / allowPortParams 是两个方法的显式入参形状。
type rulesParams struct {
	Action string `json:"action"`
	Chain  string `json:"chain,omitempty"`
}

type allowPortParams struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// RulesResult / AllowPortResult 是两个方法的结构化结果。
type RulesResult struct {
	Action  string `json:"action"`
	Chain   string `json:"chain"`
	Rules   []Rule `json:"rules"`
	Count   int    `json:"count"`
	Applied bool   `json:"applied"`
}

type AllowPortResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Applied  bool   `json:"applied"`
}
