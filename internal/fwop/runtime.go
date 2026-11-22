package fwop

import (
	"errors"
	"os"
	"strconv"
)

// Status 探测首选后端并读取状态。探测失败（如非 root）不返回协议错误，
// 而是写入 StatusResult.Error，让上层 UI 仍能展示后端与原因。
//
// ADR-0018：非 root 且注入了内核 root-action 通道时，status 经通道执行
// ufw-status / iptables-s；通道也不可用时显式返回 available=false +
// error_code=E_NEED_ROOT + hint（禁止静默失败或渲染成"无数据"）。
func (r *Runtime) Status() (StatusResult, error) {
	backend := r.detect()
	status := StatusResult{Backend: backend}
	if backend == BackendNone {
		status.Error = "未检测到 ufw 或 iptables 后端"
		return status, nil
	}
	if r.rootAction != nil && !isRoot() {
		if err := r.statusViaRootAction(backend, &status); err != nil {
			status.ErrorCode = "E_NEED_ROOT"
			status.Hint = rootActionHint()
			status.Error = "E_NEED_ROOT: 非 root，且 root-action 通道不可用：" + displayError(err)
			return status, nil
		}
		return status, nil
	}
	switch backend {
	case BackendUFW:
		path, _ := r.resolve(BackendUFW)
		output, err := r.run([]string{path, "status", "verbose"})
		if err != nil {
			status.Error = displayError(err)
			if isPermissionError(err) {
				status.ErrorCode = "E_NEED_ROOT"
				status.Hint = rootActionHint()
			}
			return status, nil
		}
		parsed := parseUfwStatusVerbose(string(output))
		status.Available = true
		status.Enabled = parsed.enabled
		status.DefaultIn = parsed.defaultIn
		status.RulesCount = parsed.count
	case BackendIptables:
		path, _ := r.resolve(BackendIptables)
		output, err := r.run([]string{path, "-S"})
		if err != nil {
			status.Error = displayError(err)
			if isPermissionError(err) {
				status.ErrorCode = "E_NEED_ROOT"
				status.Hint = rootActionHint()
			}
			return status, nil
		}
		parsed := parseIptablesS(string(output))
		status.Available = true
		status.Enabled = true // iptables 无全局开关，规则集存在即视为生效
		status.DefaultIn = parsed.defaultIn
		status.RulesCount = len(parsed.rules)
	}
	return status, nil
}

// statusViaRootAction 经内核 root-action 通道读取状态（插件自身不获得 root）。
func (r *Runtime) statusViaRootAction(backend string, status *StatusResult) error {
	switch backend {
	case BackendUFW:
		output, exitCode, err := r.rootAction("ufw-status", nil)
		if err != nil {
			return err
		}
		if exitCode != 0 {
			return opErr(ErrKindUpstream, "root-action ufw-status 退出码 %d", exitCode)
		}
		parsed := parseUfwStatusVerbose(string(output))
		status.Available = true
		status.Enabled = parsed.enabled
		status.DefaultIn = parsed.defaultIn
		status.RulesCount = parsed.count
	case BackendIptables:
		output, exitCode, err := r.rootAction("iptables-s", nil)
		if err != nil {
			return err
		}
		if exitCode != 0 {
			return opErr(ErrKindUpstream, "root-action iptables-s 退出码 %d", exitCode)
		}
		parsed := parseIptablesS(string(output))
		status.Available = true
		status.Enabled = true
		status.DefaultIn = parsed.defaultIn
		status.RulesCount = len(parsed.rules)
	}
	return nil
}

// isRoot 报告插件进程是否 root。
func isRoot() bool { return os.Geteuid() == 0 }

// isPermissionError 报告命令失败是否属于权限类（决定是否给 E_NEED_ROOT）。
func isPermissionError(err error) bool {
	var opErrValue *OpError
	return errors.As(err, &opErrValue) && opErrValue.Kind == ErrKindPermission
}

// rootActionHint 是"下一步怎么做"的可操作提示（ADR-0018 降级硬要求）。
func rootActionHint() string {
	return "需 root 权限：请用 sudo/systemd 启动 kored，或让内核经 " +
		"POST /api/v1/plugins/firewall/root-action 执行 ufw-status / iptables-s"
}

// Rules 列出指定后端（缺省自动探测）的规则。
func (r *Runtime) Rules(requested string) (RulesResult, error) {
	backend, err := r.selectBackend(requested)
	if err != nil {
		return RulesResult{}, err
	}
	switch backend {
	case BackendUFW:
		parsed, err := r.numberedRules()
		if err != nil {
			return RulesResult{}, err
		}
		rules := parsed.rules
		if rules == nil {
			rules = []Rule{}
		}
		return RulesResult{Backend: backend, Rules: rules, Count: len(rules)}, nil
	case BackendIptables:
		path, _ := r.resolve(BackendIptables)
		output, err := r.run([]string{path, "-S"})
		if err != nil {
			return RulesResult{}, err
		}
		parsed := parseIptablesS(string(output))
		rules := parsed.rules
		if rules == nil {
			rules = []Rule{}
		}
		return RulesResult{Backend: backend, Rules: rules, Count: len(rules)}, nil
	}
	return RulesResult{}, opErr(ErrKindUnsupported, "不支持的后端: %s", backend)
}

// numberedRules 读取并解析 `ufw status numbered`。
func (r *Runtime) numberedRules() (ufwStatus, error) {
	path, ok := r.resolve(BackendUFW)
	if !ok {
		return ufwStatus{}, opErr(ErrKindUnsupported, "未检测到 ufw（ufw 未安装或不在固定路径）")
	}
	output, err := r.run([]string{path, "status", "numbered"})
	if err != nil {
		return ufwStatus{}, err
	}
	return parseUfwStatusNumbered(string(output)), nil
}

// selectBackend 解析 rules 的 backend 参数：空串自动探测，显式值必须是 ufw/iptables。
func (r *Runtime) selectBackend(requested string) (string, error) {
	switch requested {
	case "":
		backend := r.detect()
		if backend == BackendNone {
			return "", opErr(ErrKindUnsupported, "未检测到 ufw 或 iptables 后端")
		}
		return backend, nil
	case BackendUFW, BackendIptables:
		if _, ok := r.resolve(requested); !ok {
			return "", opErr(ErrKindUnsupported, "未检测到 %s 后端", requested)
		}
		return requested, nil
	}
	return "", opErr(ErrKindInvalid, "backend 必须是 ufw / iptables，或省略以自动探测")
}

// Allow 放行端口（仅 ufw）。dryRun=true 只返回将要执行的 argv，不执行。
func (r *Runtime) Allow(port int, proto, from, comment string, dryRun bool) (WriteResult, error) {
	path, ok := r.resolve(BackendUFW)
	if !ok {
		return WriteResult{}, opErr(ErrKindUnsupported, "写操作仅支持 ufw 后端：未检测到 ufw")
	}
	argv := buildUfwRuleCommand(path, ActionAllow, port, proto, from, comment)
	result := WriteResult{
		DryRun:  dryRun,
		Backend: BackendUFW,
		Command: argv,
		Rule: Rule{
			Action: ActionAllow, Direction: DirectionIn, Proto: proto,
			Port: PortValue(strconv.Itoa(port)), From: from, Comment: comment,
		},
	}
	if dryRun {
		return result, nil
	}
	if _, err := r.run(argv); err != nil {
		return WriteResult{}, err
	}
	result.Applied = true
	return result, nil
}

// Deny 拒绝端口（仅 ufw）。SSH 端口保护在调用层先行拦截，dry-run 同样被拒。
func (r *Runtime) Deny(port int, proto, from string, dryRun bool) (WriteResult, error) {
	path, ok := r.resolve(BackendUFW)
	if !ok {
		return WriteResult{}, opErr(ErrKindUnsupported, "写操作仅支持 ufw 后端：未检测到 ufw")
	}
	argv := buildUfwRuleCommand(path, ActionDeny, port, proto, from, "")
	result := WriteResult{
		DryRun:  dryRun,
		Backend: BackendUFW,
		Command: argv,
		Rule: Rule{
			Action: ActionDeny, Direction: DirectionIn, Proto: proto,
			Port: PortValue(strconv.Itoa(port)), From: from,
		},
	}
	if dryRun {
		return result, nil
	}
	if _, err := r.run(argv); err != nil {
		return WriteResult{}, err
	}
	result.Applied = true
	return result, nil
}

// Delete 按 ufw 编号删除规则。删除前先回读规则内容做 SSH 护栏目判断：
// 目标不存在返回 notfound；目标是入站 SSH 放行规则返回 permission。
func (r *Runtime) Delete(index int, dryRun bool) (DeleteResult, error) {
	path, ok := r.resolve(BackendUFW)
	if !ok {
		return DeleteResult{}, opErr(ErrKindUnsupported, "deleteRule 仅支持 ufw 后端：未检测到 ufw")
	}
	parsed, err := r.numberedRules()
	if err != nil {
		return DeleteResult{}, err
	}
	target, found := findRuleByIndex(parsed.rules, index)
	if !found {
		return DeleteResult{}, opErr(ErrKindNotFound, "ufw 编号 %d 不存在（当前共 %d 条可列出规则）", index, len(parsed.rules))
	}
	if perr := r.checkDeleteSSHAllow(target); perr != nil {
		return DeleteResult{}, opErr(ErrKindPermission, "%s", perr.Message)
	}
	argv := buildUfwDeleteCommand(path, index)
	result := DeleteResult{DryRun: dryRun, Backend: BackendUFW, Command: argv, Deleted: target}
	if dryRun {
		return result, nil
	}
	if _, err := r.run(argv); err != nil {
		return DeleteResult{}, err
	}
	result.Applied = true
	return result, nil
}

// displayError 去掉内部错误类别前缀，只把可读原因写进 status.error。
func displayError(err error) string {
	var oe *OpError
	if errors.As(err, &oe) {
		return oe.Message
	}
	return err.Error()
}

// findRuleByIndex 在规则列表里按 ufw 编号查找。
func findRuleByIndex(rules []Rule, index int) (Rule, bool) {
	for _, rule := range rules {
		if rule.Index == index {
			return rule, true
		}
	}
	return Rule{}, false
}
