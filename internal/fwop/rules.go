package fwop

import (
	"encoding/json"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// callRules 处理 firewall.rules：校验 action/chain 后返回规则列表。
// 骨架口径下执行面返回空列表且 applied=false，不触碰真实防火墙链。
func callRules(raw json.RawMessage, exec Executor) (json.RawMessage, *pluginapi.Error) {
	var p rulesParams
	if perr := decodeParams(raw, &p); perr != nil {
		return nil, perr
	}
	if perr := checkAction(p.Action); perr != nil {
		return nil, perr
	}
	chain := p.Chain
	if chain == "" {
		chain = "kore-input"
	}
	if perr := checkChain(chain); perr != nil {
		return nil, perr
	}
	rules, err := exec.Rules(p.Action, chain)
	if err != nil {
		return nil, classify(err)
	}
	if rules == nil {
		rules = []Rule{}
	}
	if len(rules) > maxRules {
		return nil, internalErr("规则数超过上限")
	}
	return encode(RulesResult{
		Action: p.Action, Chain: chain, Rules: rules,
		Count: len(rules), Applied: false,
	})
}

// checkAction 校验 firewall.rules 的 action：list/add/remove 三值之一。
func checkAction(action string) *pluginapi.Error {
	switch action {
	case "list", "add", "remove":
		return nil
	}
	return invalid("action 必须是 list/add/remove")
}

// checkChain 校验 chain 名只含安全字符，且只操作 kore: 段（提案约束）。
func checkChain(chain string) *pluginapi.Error {
	if len(chain) == 0 || len(chain) > 64 {
		return invalid("chain 长度必须在 1-64 之间")
	}
	for _, r := range chain {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == ':' || r == '_' {
			continue
		}
		return invalid("chain 只含字母/数字/-/_/:")
	}
	return nil
}
