package fwop

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// Call 执行一个 firewall 方法：归一方法名 → 参数校验 → 安全护栏 → 执行面。
// 同时接受 `firewall.<verb>` 与裸 `<verb>`。
func (r *Runtime) Call(method string, params json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	verb, ok := businessVerb(method)
	if !ok {
		return nil, errNotFound(method)
	}
	switch verb {
	case "status":
		return r.callStatus(params)
	case "rules":
		return r.callRules(params)
	case "allowPort":
		return r.callAllow(params)
	case "denyPort":
		return r.callDeny(params)
	case "deleteRule":
		return r.callDelete(params)
	}
	return nil, errNotFound(method)
}

// businessVerb 把 firewall.<verb> 或裸 <verb> 归一为动词名。
func businessVerb(method string) (string, bool) {
	verb := strings.TrimPrefix(method, "firewall.")
	switch verb {
	case "status", "rules", "allowPort", "denyPort", "deleteRule":
		return verb, true
	}
	return "", false
}

// callStatus 处理 firewall.status；参数可省略。
func (r *Runtime) callStatus(params json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	var p struct{}
	if perr := decodeOptional(params, &p); perr != nil {
		return nil, perr
	}
	result, err := r.Status()
	if err != nil {
		return nil, classify(err)
	}
	return encode(result)
}

// callRules 处理 firewall.rules；backend 可省略。
func (r *Runtime) callRules(params json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	var p rulesParams
	if perr := decodeOptional(params, &p); perr != nil {
		return nil, perr
	}
	result, err := r.Rules(p.Backend)
	if err != nil {
		return nil, classify(err)
	}
	return encode(result)
}

// callAllow 处理 firewall.allowPort：参数校验后交给 ufw 执行（或 dry-run 返回命令）。
func (r *Runtime) callAllow(params json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	if perr := r.requireAdmin(); perr != nil {
		return nil, perr
	}
	var p allowPortParams
	if perr := decodeParams(params, &p); perr != nil {
		return nil, perr
	}
	if perr := validatePort(p.Port); perr != nil {
		return nil, perr
	}
	proto, perr := normalizeProto(p.Proto)
	if perr != nil {
		return nil, perr
	}
	from, perr := normalizeFrom(p.From)
	if perr != nil {
		return nil, perr
	}
	if perr := validateComment(p.Comment); perr != nil {
		return nil, perr
	}
	result, err := r.Allow(p.Port, proto, from, strings.TrimSpace(p.Comment), p.DryRun)
	if err != nil {
		return nil, classify(err)
	}
	return encode(result)
}

// callDeny 处理 firewall.denyPort：SSH 保护先于协议/来源校验与 dry-run。
func (r *Runtime) callDeny(params json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	if perr := r.requireAdmin(); perr != nil {
		return nil, perr
	}
	var p denyPortParams
	if perr := decodeParams(params, &p); perr != nil {
		return nil, perr
	}
	if perr := validatePort(p.Port); perr != nil {
		return nil, perr
	}
	if perr := r.checkDenySSHPort(p.Port); perr != nil {
		return nil, perr
	}
	proto, perr := normalizeProto(p.Proto)
	if perr != nil {
		return nil, perr
	}
	from, perr := normalizeFrom(p.From)
	if perr != nil {
		return nil, perr
	}
	result, err := r.Deny(p.Port, proto, from, p.DryRun)
	if err != nil {
		return nil, classify(err)
	}
	return encode(result)
}

// callDelete 处理 firewall.deleteRule：按 ufw 编号删除，SSH 护栏目在 Delete 内判定。
func (r *Runtime) callDelete(params json.RawMessage) (json.RawMessage, *pluginapi.Error) {
	if perr := r.requireAdmin(); perr != nil {
		return nil, perr
	}
	var p deleteRuleParams
	if perr := decodeParams(params, &p); perr != nil {
		return nil, perr
	}
	if p.Index < 1 {
		return nil, invalid("index 必须是 ufw 编号（≥1）")
	}
	result, err := r.Delete(p.Index, p.DryRun)
	if err != nil {
		return nil, classify(err)
	}
	return encode(result)
}

// requireAdmin 校验插件自身声明的 system:admin 能力；缺失时写操作一律拒绝。
// 内核在调用前已按 info.json 校验授权，这里是插件侧的纵深防御。
func (r *Runtime) requireAdmin() *pluginapi.Error {
	if r.policy.canAdmin() {
		return nil
	}
	return unauthorized("写操作需要 system:admin capability")
}

// classify 把执行面错误映射为协议错误码：四类故障各有对应，其余归 E_INTERNAL。
func classify(err error) *pluginapi.Error {
	var fe *FaultError
	if errors.As(err, &fe) {
		switch fe.Kind {
		case FaultKill:
			return upstream("进程被信号 9 终止: " + fe.Message)
		case FaultTimeout:
			return upstream("调用超时: " + fe.Message)
		case FaultDisk:
			return internalErr("磁盘满: " + fe.Message)
		case FaultCgroup:
			return unsupported("cgroup 限额触发: " + fe.Message)
		}
	}
	var oe *OpError
	if errors.As(err, &oe) {
		switch oe.Kind {
		case ErrKindInvalid:
			return invalid(oe.Message)
		case ErrKindNotFound:
			return notFound(oe.Message)
		case ErrKindUnauthorized:
			return unauthorized(oe.Message)
		case ErrKindPermission:
			// 权限类失败只可能来自"需要 root"（ufw/iptables 都要求 root）：
			// 按 ADR-0018 返回 E_NEED_ROOT（HTTP 403），不再误报成 401 登录失效。
			return needRoot(oe.Message)
		case ErrKindUnsupported:
			return unsupported(oe.Message)
		case ErrKindUpstream:
			return upstream(oe.Message)
		}
		return internalErr(oe.Message)
	}
	return internalErr("执行面失败: " + err.Error())
}

// 协议错误构造函数。
func invalid(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INVALID, Message: msg}
}

func unauthorized(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_UNAUTHORIZED, Message: msg}
}

// needRoot 构造 E_NEED_ROOT + detail.hint（内核 HTTP 层把 hint 提升为顶层字段）。
func needRoot(msg string) *pluginapi.Error {
	detail, _ := json.Marshal(struct {
		Hint string `json:"hint"`
	}{Hint: rootActionHint()})
	return &pluginapi.Error{Code: CodeNeedRoot, Message: msg, Detail: detail}
}

func notFound(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_NOTFOUND, Message: msg}
}

func errNotFound(method string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_NOTFOUND, Message: "未知方法: " + method}
}

func upstream(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_UPSTREAM, Message: msg}
}

func internalErr(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: msg}
}

func unsupported(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_UNSUPPORTED, Message: msg}
}
