package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pengtang1024/kore-plugin-firewall/internal/fwop"
	"github.com/pengtang1024/kore-plugin-firewall/internal/plugincfg"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// embeddedInfo 是随二进制发布的内嵌清单：只含握手字段，字节稳定。
// 刻意不内嵌 info.json——其 size_bytes 会被打包脚本回填，若内嵌会使二进制
// 随清单自指震荡，破坏 make dist 的 sha 确定性（manifest.json 提交态固定）。
//
//go:embed manifest.json
var embeddedInfo []byte

// manifest 是 info.json 中插件运行期真正需要的字段，其余字段归内核校验。
type manifest struct {
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	Protocol     string   `json:"protocol"`
	RequiresKore string   `json:"requires_kore"`
	Capabilities []string `json:"capabilities"`
}

// 配置环境变量（文件不存在时才生效，优先级 config.json > env > 默认值，见 PLUGIN-CONFIG §4）。
const (
	// EnvDefaultBackend 覆盖默认防火墙后端（auto/ufw/iptables）。
	EnvDefaultBackend = "KORE_FIREWALL_DEFAULT_BACKEND"
	// EnvSSHPorts 覆盖 SSH 保护端口（逗号分隔整数，始终含 22）。
	EnvSSHPorts = "KORE_SSH_PORT"
	// EnvDryRunDefault 覆盖写操作默认 dry_run（true/false）。
	EnvDryRunDefault = "KORE_FIREWALL_DRY_RUN"
)

// fileValues 是 <state_dir>/config.json 的显式形状（G-24：不引入 object/any）。
// 三个字段都对应 fwop 真实存在的能力，不臆造未实现项。
type fileValues struct {
	// DefaultBackend 是 firewall.rules 未显式指定 backend 时使用的后端：auto/ufw/iptables。
	DefaultBackend string `json:"default_backend"`
	// SSHPorts 是 denyPort / deleteRule 的 SSH 保护端口（始终含 22）。
	SSHPorts []int `json:"ssh_ports"`
	// DryRunDefault 是写方法未显式指定 dry_run 时的默认值。
	DryRunDefault bool `json:"dry_run_default"`
}

// config 是插件运行期配置：配置契约（config.json）+ 环境变量 + 内嵌清单。
type config struct {
	socket       string
	id           string
	token        string
	version      string
	requiresKore string
	capabilities []string
	startedAt    time.Time
	// stateDir 是插件状态目录（KORE_STATE_DIR）。
	stateDir string
	// store 是配置文件的 0600 原子读写器。
	store *plugincfg.Store
	// values / source 是 config.get 的当前值与来源（file / env / default）。
	values fileValues
	source string
}

// loadConfig 读取配置契约与环境变量，解析内嵌清单。
func loadConfig() (*config, error) {
	var m manifest
	if err := json.Unmarshal(embeddedInfo, &m); err != nil {
		return nil, fmt.Errorf("解析内嵌 manifest.json: %w", err)
	}
	if m.Protocol != pluginapi.Protocol {
		return nil, fmt.Errorf("info.json.protocol=%q 与 SDK 协议 %q 不一致", m.Protocol, pluginapi.Protocol)
	}
	if err := plugincfg.ValidateSchema(configSchema()); err != nil {
		return nil, fmt.Errorf("config schema 非法: %w", err)
	}
	stateDir := strings.TrimSpace(os.Getenv("KORE_STATE_DIR"))
	store := plugincfg.NewStore(stateDir)
	values, source, err := resolveValues(store)
	if err != nil {
		return nil, err
	}
	cfg := &config{
		socket:       os.Getenv("KORE_PLUGIN_SOCK"),
		id:           os.Getenv("KORE_PLUGIN_ID"),
		token:        os.Getenv("KORE_PLUGIN_TOKEN"),
		version:      m.Version,
		requiresKore: m.RequiresKore,
		capabilities: m.Capabilities,
		startedAt:    time.Now(),
		stateDir:     stateDir,
		store:        store,
		values:       values,
		source:       source,
	}
	if cfg.id == "" {
		cfg.id = m.ID
	}
	if cfg.socket == "" {
		return nil, fmt.Errorf("缺少环境变量 KORE_PLUGIN_SOCK")
	}
	return cfg, nil
}

// defaultValues 是代码默认值。
func defaultValues() fileValues {
	return fileValues{
		DefaultBackend: fwop.BackendAuto,
		SSHPorts:       []int{fwop.DefaultSSHPort},
		DryRunDefault:  false,
	}
}

// resolveValues 实现优先级 config.json > 环境变量 > 代码默认值（PLUGIN-CONFIG §4）。
func resolveValues(store *plugincfg.Store) (fileValues, string, error) {
	if store.Exists() {
		raw, _, err := store.Read()
		if err != nil {
			return fileValues{}, "", err
		}
		var values fileValues
		if err := json.Unmarshal(raw, &values); err != nil {
			return fileValues{}, "", fmt.Errorf("解析插件配置 %s: %w", store.Path(), err)
		}
		normalized, perr := validateValues(fillDefaults(values))
		if perr != nil {
			return fileValues{}, "", fmt.Errorf("插件配置 %s 非法: %s", store.Path(), perr.Message)
		}
		return normalized, plugincfg.SourceFile, nil
	}

	values := defaultValues()
	source := plugincfg.SourceDefault
	if raw := strings.TrimSpace(os.Getenv(EnvDefaultBackend)); raw != "" {
		values.DefaultBackend = raw
		source = plugincfg.SourceEnv
	}
	if raw := strings.TrimSpace(os.Getenv(EnvSSHPorts)); raw != "" {
		ports, err := fwop.ParseSSHPorts(raw)
		if err != nil {
			return fileValues{}, "", fmt.Errorf("%s 非法: %w", EnvSSHPorts, err)
		}
		values.SSHPorts = ports
		source = plugincfg.SourceEnv
	}
	if raw := strings.TrimSpace(os.Getenv(EnvDryRunDefault)); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fileValues{}, "", fmt.Errorf("%s=%q 非法：必须是 true/false", EnvDryRunDefault, raw)
		}
		values.DryRunDefault = value
		source = plugincfg.SourceEnv
	}
	normalized, perr := validateValues(fillDefaults(values))
	if perr != nil {
		return fileValues{}, "", perr
	}
	return normalized, source, nil
}

// fillDefaults 把零值字段补成默认值（config.json 允许只写关心的字段）。
func fillDefaults(values fileValues) fileValues {
	defaults := defaultValues()
	if strings.TrimSpace(values.DefaultBackend) == "" {
		values.DefaultBackend = defaults.DefaultBackend
	}
	if len(values.SSHPorts) == 0 {
		values.SSHPorts = defaults.SSHPorts
	}
	return values
}

// validateValues 校验并归一化配置；启动加载与 config.set 共用同一套规则。
func validateValues(values fileValues) (fileValues, *pluginapi.Error) {
	backend := strings.ToLower(strings.TrimSpace(values.DefaultBackend))
	switch backend {
	case fwop.BackendAuto, fwop.BackendUFW, fwop.BackendIptables:
	default:
		return fileValues{}, invalidConfig("default_backend 不支持 " + values.DefaultBackend + "：仅允许 auto/ufw/iptables")
	}
	values.DefaultBackend = backend

	// 复用 fwop 的 SSH 端口归一化（校验 1-65535、去重、强制含 22）。
	settings, err := fwop.NormalizeSettings(fwop.Settings{
		SSHPorts:       values.SSHPorts,
		DefaultBackend: backend,
		DryRunDefault:  values.DryRunDefault,
	})
	if err != nil {
		return fileValues{}, invalidConfig("ssh_ports 非法: " + err.Error())
	}
	values.SSHPorts = append([]int(nil), settings.SSHPorts...)
	return values, nil
}

// configSchema 是 config.get 返回的表单描述（PLUGIN-CONFIG §2）。
// 本仓无凭据类字段（不读写任何口令/token），故没有 sensitive=true 的字段；
// plugincfg 层完整保留 sensitive 掩码能力，若将来引入凭据可直接标注（G-30）。
func configSchema() plugincfg.Schema {
	defaults := defaultValues()
	return plugincfg.Schema{
		Title: "防火墙规则与保护配置",
		Fields: []plugincfg.Field{
			{
				Key: "default_backend", Label: "默认防火墙后端", Type: plugincfg.TypeSelect,
				Default:  mustJSON(defaults.DefaultBackend),
				Required: true,
				Help:     "firewall.rules 未指定后端时使用：auto 按 ufw → iptables 自动探测；也可强制指定（需已安装）。",
				Options:  []string{fwop.BackendAuto, fwop.BackendUFW, fwop.BackendIptables},
			},
			{
				Key: "ssh_ports", Label: "SSH 保护端口", Type: plugincfg.TypeList, Item: plugincfg.TypeInt,
				Default:  mustJSON(defaults.SSHPorts),
				Required: false,
				Help:     "拒绝屏蔽或删除这些端口的入站放行规则；端口 22 始终受保护，不可移除。",
				Min:      intPtr(1),
				Max:      intPtr(65535),
			},
			{
				Key: "dry_run_default", Label: "写操作默认试运行", Type: plugincfg.TypeBool,
				Default:  mustJSON(defaults.DryRunDefault),
				Required: false,
				Help:     "开启后，放行/拒绝/删除/启停端口规则在未显式指定 dry_run 时只返回将要执行的命令，不实际修改防火墙。",
			},
		},
	}
}

// validateValueTypes 按 schema 显式校验每个字段的 JSON 类型（PLUGIN-CONFIG §8）。
// 只检查本次提交的字段；类型不符时给出「哪一项 + 应是什么类型 + 怎么改」。
func validateValueTypes(raw json.RawMessage) *pluginapi.Error {
	var provided map[string]json.RawMessage
	if err := json.Unmarshal(raw, &provided); err != nil {
		return invalidConfig("values 不是合法的 JSON 对象，请检查括号与逗号后重试")
	}
	for _, field := range configSchema().Fields {
		value, ok := provided[field.Key]
		if !ok {
			continue
		}
		text := strings.TrimSpace(string(value))
		if text == "null" {
			return invalidConfig(field.Label + " 不能为 null，请填写正确的" + field.Type + "值或删除该项")
		}
		switch field.Type {
		case plugincfg.TypeInt:
			if n, err := strconv.Atoi(text); err != nil || n < 0 {
				return invalidConfig(field.Label + " 必须是整数（收到 " + text + "），请填写 0 或正整数")
			}
		case plugincfg.TypeBool:
			if text != "true" && text != "false" {
				return invalidConfig(field.Label + " 必须是 true 或 false（收到 " + text + "），请改为布尔值")
			}
		case plugincfg.TypeString, plugincfg.TypeSelect:
			if len(text) == 0 || text[0] != '"' {
				return invalidConfig(field.Label + " 必须是文本（收到 " + text + "），请加英文双引号")
			}
		case plugincfg.TypeList:
			if len(text) == 0 || text[0] != '[' {
				return invalidConfig(field.Label + " 必须是数组（收到 " + text + "），请用 [ ] 包裹并填写列表项")
			}
			var items []json.RawMessage
			if err := json.Unmarshal(value, &items); err != nil {
				return invalidConfig(field.Label + " 数组格式错误，请检查逗号与括号后重试")
			}
			for i, item := range items {
				part := strings.TrimSpace(string(item))
				if n, err := strconv.Atoi(part); err != nil || n < 1 || n > 65535 {
					return invalidConfig(field.Label + " 第 " + strconv.Itoa(i+1) + " 项必须是 1-65535 的端口整数（收到 " + part + "）")
				}
			}
		}
	}
	return nil
}

// invalidConfig 构造配置校验错误（E_INVALID）。
func invalidConfig(message string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INVALID, Message: message}
}

// mustJSON 把标量编成 json.RawMessage（schema 的 default 字段）。
func mustJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return encoded
}

// intPtr 返回整数指针（schema 的 min/max）。
func intPtr(value int) *int { return &value }

// settings 把配置映射成 fwop 可热更的运行期设置。
func (c *config) settings() fwop.Settings {
	return fwop.Settings{
		SSHPorts:       append([]int(nil), c.values.SSHPorts...),
		DefaultBackend: c.values.DefaultBackend,
		DryRunDefault:  c.values.DryRunDefault,
	}
}

// applySettings 把当前配置注入执行面。loadConfig 成功后调用一次；
// config.set 原子写成功后也调用一次，使新值在同进程内立即生效（PLUGIN-CONFIG §5）。
func (c *config) applySettings(fw *fwop.Runtime) error {
	return fw.UpdateSettings(c.settings())
}

// configGet 组装 config.get 结果：schema + 当前值（敏感字段掩码）+ 来源。
func configGet(c *config) (json.RawMessage, *pluginapi.Error) {
	values, err := json.Marshal(c.values)
	if err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化当前配置失败: " + err.Error()}
	}
	masked, err := plugincfg.MaskValues(configSchema(), values)
	if err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "掩码配置值失败: " + err.Error()}
	}
	result := plugincfg.GetResult{Schema: configSchema(), Values: masked, Source: c.source}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化 config.get 结果失败: " + err.Error()}
	}
	return encoded, nil
}

// configSet 按「校验 → 原子写 → 更新内存 → 热生效提示」顺序保存配置（PLUGIN-CONFIG §3/§5）。
// fw 可为 nil（单测纯契约形状时用），非 nil 时会在原子写成功后注入执行面。
func configSet(raw json.RawMessage, c *config, fw *fwop.Runtime) (json.RawMessage, *pluginapi.Error) {
	var params plugincfg.SetParams
	if len(raw) == 0 || string(raw) == "null" {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "缺少必填字段 values"}
	}
	if raw[0] != '{' {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "params 必须是 JSON 对象"}
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "params 解析失败: " + err.Error()}
	}
	if len(params.Values) == 0 || string(params.Values) == "null" || params.Values[0] != '{' {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "values 必须是 JSON 对象"}
	}

	// 字段级类型预检：按 schema 显式类型给出「哪一项错 + 怎么改」的中文（§8），
	// 不把 json.Unmarshal 的英文原文直接抛给用户。
	if perr := validateValueTypes(params.Values); perr != nil {
		return nil, perr
	}
	// 以当前值为基线做局部更新：未提供的字段保持原值。
	candidate := c.values
	if err := json.Unmarshal(params.Values, &candidate); err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INVALID, Message: "values 解析失败，请检查各字段类型是否正确"}
	}
	normalized, perr := validateValues(fillDefaults(candidate))
	if perr != nil {
		return nil, perr
	}
	if c.store.Path() == "" {
		return nil, &pluginapi.Error{
			Code:    pluginapi.E_INTERNAL,
			Message: "KORE_STATE_DIR 未设置，无法保存插件配置",
			Detail:  json.RawMessage(`{"hint":"插件由内核启动时会注入 KORE_STATE_DIR；本地单独调试请先设置该环境变量。"}`),
		}
	}
	payload, marshalErr := json.Marshal(normalized)
	if marshalErr != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化配置失败: " + marshalErr.Error()}
	}
	if writeErr := c.store.Write(payload); writeErr != nil {
		return nil, &pluginapi.Error{
			Code:    pluginapi.E_INTERNAL,
			Message: "保存插件配置失败: " + writeErr.Error(),
			Detail:  json.RawMessage(`{"hint":"检查 KORE_STATE_DIR 是否可写（目录需 0700 且属主为运行用户）。"}`),
		}
	}

	// 原子写成功后才更新内存与执行面；任一步之前的失败都不改内存、不写半份文件。
	c.values = normalized
	c.source = plugincfg.SourceFile
	warnings := []string{}
	if fw != nil {
		if err := c.applySettings(fw); err != nil {
			// 文件已落盘但注入失败：如实告知需重启生效，不谎报 applied。
			warnings = append(warnings, "配置已保存，但热生效失败（"+err.Error()+"），请重启 kored 后生效")
		}
	}
	applied := len(warnings) == 0
	result := plugincfg.SetResult{
		Saved: true, Applied: applied, RestartRequired: !applied, Warnings: warnings,
	}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化 config.set 结果失败: " + marshalErr.Error()}
	}
	return encoded, nil
}

// reload 重新从配置文件加载值并热注入执行面（kore.reload 用）。
func (c *config) reload(fw *fwop.Runtime) (json.RawMessage, *pluginapi.Error) {
	values, source, err := resolveValues(c.store)
	if err != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "重载配置失败: " + err.Error()}
	}
	c.values = values
	c.source = source
	if fw != nil {
		if err := c.applySettings(fw); err != nil {
			return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "热注入配置失败: " + err.Error()}
		}
	}
	payload, marshalErr := json.Marshal(c.values)
	if marshalErr != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化配置失败: " + marshalErr.Error()}
	}
	// 摘要用 sha256 前 8 字节，与协议 digest 形状一致。
	sum := sha256.Sum256(payload)
	result := struct {
		OK           bool   `json:"ok"`
		ConfigDigest string `json:"config_digest"`
	}{OK: true, ConfigDigest: hex.EncodeToString(sum[:8])}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return nil, &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "序列化 reload 结果失败: " + marshalErr.Error()}
	}
	return encoded, nil
}
