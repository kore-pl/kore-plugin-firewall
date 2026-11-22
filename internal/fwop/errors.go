package fwop

import "fmt"

// FaultKind 标识一次故障注入的类别（与 file / monitor / process 插件同一口径）。
type FaultKind string

// 四类故障注入类别。
const (
	FaultNone    FaultKind = ""
	FaultKill    FaultKind = "kill"
	FaultTimeout FaultKind = "timeout"
	FaultDisk    FaultKind = "disk"
	FaultCgroup  FaultKind = "cgroup"
)

// FaultError 是执行面注入的故障错误，classify 将其映射为协议错误码。
type FaultError struct {
	Kind    FaultKind
	Message string
}

// Error 实现 error 接口，输出 "<类别>: <说明>"。
func (e *FaultError) Error() string { return fmt.Sprintf("%s: %s", e.Kind, e.Message) }

// NewFaultError 构造给定类别的故障错误，供故障注入 Runner 使用。
func NewFaultError(kind FaultKind, message string) *FaultError {
	return &FaultError{Kind: kind, Message: message}
}

// ErrKind 是执行面业务错误的语义类别，classify 将其映射为协议错误码。
type ErrKind string

// 执行面业务错误类别。
const (
	ErrKindInvalid     ErrKind = "invalid"
	ErrKindNotFound    ErrKind = "notfound"
	ErrKindPermission  ErrKind = "permission"
	ErrKindUnsupported ErrKind = "unsupported"
	ErrKindUpstream    ErrKind = "upstream"
	ErrKindInternal    ErrKind = "internal"
)

// OpError 是执行面返回的可分类业务错误。
type OpError struct {
	Kind    ErrKind
	Message string
}

// Error 实现 error 接口。
func (e *OpError) Error() string { return string(e.Kind) + ": " + e.Message }

// opErr 构造 OpError。
func opErr(kind ErrKind, format string, args ...any) *OpError {
	return &OpError{Kind: kind, Message: fmt.Sprintf(format, args...)}
}
