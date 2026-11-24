package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore-plugin-firewall/internal/fwop"
	"github.com/pengtang1024/kore-plugin-firewall/internal/plugincfg"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// newConfigFixture 构造带隔离 KORE_STATE_DIR 的配置与执行面，
// 不触碰宿主防火墙，也不污染真实状态目录（PLUGIN-CONFIG §3/§10）。
func newConfigFixture(t *testing.T) (*config, *fwop.Runtime) {
	t.Helper()
	stateDir := t.TempDir()
	cfg := &config{
		id:           "firewall",
		version:      "0.2.7",
		requiresKore: ">=0.1.0 <0.2.0",
		capabilities: []string{"system:admin"},
		startedAt:    time.Now(),
		stateDir:     stateDir,
		store:        plugincfg.NewStore(stateDir),
		values:       defaultValues(),
		source:       plugincfg.SourceDefault,
	}
	runtime, err := fwop.New(fwop.Options{
		Capabilities: []string{"system:admin"},
		SSHPorts:     []int{fwop.DefaultSSHPort},
		Runner:       &testRunner{},
		Resolve: func(name string) (string, bool) {
			if name == fwop.BackendUFW || name == fwop.BackendIptables {
				return "/usr/sbin/" + name, true
			}
			return "", false
		},
	})
	if err != nil {
		t.Fatalf("构造执行面失败: %v", err)
	}
	return cfg, runtime
}

// configRequest 经 dispatch 发 config.* 请求，返回响应。
func configRequest(t *testing.T, cfg *config, fw *fwop.Runtime, method, params string) *pluginapi.Response {
	t.Helper()
	req := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: "cfg-id", ReqID: "cfg-req",
		Method: method, Params: json.RawMessage(params),
	}
	resp, shutdown := dispatch(req, cfg, fw, testLogger())
	if shutdown {
		t.Fatalf("%s 不应触发 shutdown", method)
	}
	return resp
}

// TestConfigGetSchemaCompliance §2：schema 显式枚举、字段必填项齐全、default 类型一致。
func TestConfigGetSchemaCompliance(t *testing.T) {
	cfg, fw := newConfigFixture(t)
	for _, method := range []string{"firewall.config.get", "config.get"} {
		resp := configRequest(t, cfg, fw, method, "")
		if resp.Error != nil {
			t.Fatalf("%s 意外失败: %+v", method, resp.Error)
		}
		var result plugincfg.GetResult
		if err := json.Unmarshal(resp.Result, &result); err != nil {
			t.Fatalf("%s 解析失败: %v（原文 %s）", method, err, resp.Result)
		}
		if err := plugincfg.ValidateSchema(result.Schema); err != nil {
			t.Fatalf("%s schema 不合规: %v", method, err)
		}
		if result.Schema.Title == "" || len(result.Schema.Fields) != 3 {
			t.Fatalf("%s 字段数=%d，期望 3 个真实能力字段", method, len(result.Schema.Fields))
		}
		if result.Source != plugincfg.SourceDefault {
			t.Fatalf("%s 初始 source=%q，期望 default", method, result.Source)
		}
		var values map[string]json.RawMessage
		if err := json.Unmarshal(result.Values, &values); err != nil {
			t.Fatalf("values 不是对象: %v", err)
		}
		for _, key := range []string{"default_backend", "ssh_ports", "dry_run_default"} {
			if _, ok := values[key]; !ok {
				t.Fatalf("%s values 缺字段 %s", method, key)
			}
		}
	}
}

// TestConfigSetRoundTripHotApply §3/§4/§5：set 后落盘 0600、source=file、
// 三字段在同进程内热生效（PID 不变，下一次业务调用即使用新值）。
func TestConfigSetRoundTripHotApply(t *testing.T) {
	cfg, fw := newConfigFixture(t)
	pidBefore := os.Getpid()

	params := `{"values":{"default_backend":"iptables","ssh_ports":[22,2222],"dry_run_default":true}}`
	resp := configRequest(t, cfg, fw, "firewall.config.set", params)
	if resp.Error != nil {
		t.Fatalf("config.set 意外失败: %+v", resp.Error)
	}
	var setResult plugincfg.SetResult
	if err := json.Unmarshal(resp.Result, &setResult); err != nil {
		t.Fatalf("解析 config.set 结果失败: %v", err)
	}
	if !setResult.Saved || !setResult.Applied || setResult.RestartRequired || len(setResult.Warnings) != 0 {
		t.Fatalf("config.set 结果不符（应已保存且热生效）: %+v", setResult)
	}
	if os.Getpid() != pidBefore {
		t.Fatal("config.set 不应重启插件进程")
	}

	// 文件落盘且权限 0600。
	info, err := os.Stat(cfg.store.Path())
	if err != nil {
		t.Fatalf("配置文件未落盘: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("配置文件权限=%o，期望 600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(cfg.store.Path())
	if err != nil {
		t.Fatalf("回读配置文件失败: %v", err)
	}
	var persisted fileValues
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}
	if persisted.DefaultBackend != "iptables" || !persisted.DryRunDefault ||
		len(persisted.SSHPorts) != 2 || persisted.SSHPorts[1] != 2222 {
		t.Fatalf("持久化值不符: %+v", persisted)
	}

	// config.get 现在 source=file，值来自文件。
	get := configRequest(t, cfg, fw, "firewall.config.get", "")
	var got plugincfg.GetResult
	if err := json.Unmarshal(get.Result, &got); err != nil {
		t.Fatalf("解析 config.get 失败: %v", err)
	}
	if got.Source != plugincfg.SourceFile {
		t.Fatalf("set 后 source=%q，期望 file", got.Source)
	}

	// 热生效：config.set 内部已把新值注入执行面（无需重启、无需手动 UpdateSettings）。
	effective := fw.Settings()
	if effective.DefaultBackend != "iptables" || !effective.DryRunDefault ||
		len(effective.SSHPorts) != 2 || effective.SSHPorts[1] != 2222 {
		t.Fatalf("执行面未热生效: %+v", effective)
	}
	denied := configRequest(t, cfg, fw, "firewall.denyPort", `{"port":2222}`)
	if denied.Error == nil || denied.Error.Code != pluginapi.E_UNAUTHORIZED {
		t.Fatalf("热生效的 SSH 2222 保护未命中: %+v", denied.Error)
	}
	var dryRunResult struct {
		Applied bool `json:"applied"`
		DryRun  bool `json:"dry_run"`
	}
	allowed := configRequest(t, cfg, fw, "firewall.allowPort", `{"port":18080}`)
	if allowed.Error != nil {
		t.Fatalf("默认 dry-run 写操作意外失败: %+v", allowed.Error)
	}
	if err := json.Unmarshal(allowed.Result, &dryRunResult); err != nil {
		t.Fatalf("解析写结果失败: %v", err)
	}
	if dryRunResult.Applied || !dryRunResult.DryRun {
		t.Fatalf("默认 dry_run=true 未生效: %+v", dryRunResult)
	}
}

// TestConfigSetInvalid §8：非法枚举/越界端口返回 E_INVALID 且不落盘、内存不变。
func TestConfigSetInvalid(t *testing.T) {
	cfg, fw := newConfigFixture(t)
	for _, params := range []string{
		`{"values":{"default_backend":"nftables"}}`,
		`{"values":{"ssh_ports":[22,70000]}}`,
		`{"values":{"dry_run_default":"yes"}}`,
	} {
		resp := configRequest(t, cfg, fw, "firewall.config.set", params)
		if resp.Error == nil || resp.Error.Code != pluginapi.E_INVALID {
			t.Fatalf("非法值 %s 未被拒: %+v", params, resp.Error)
		}
		if !strings.Contains(resp.Error.Message, "请") && !strings.Contains(resp.Error.Message, "仅") &&
			!strings.Contains(resp.Error.Message, "必须") && !strings.Contains(resp.Error.Message, "非法") {
			t.Fatalf("错误文案未给出怎么改: %q", resp.Error.Message)
		}
		if cfg.store.Exists() {
			t.Fatalf("非法值不应落盘: %s", params)
		}
		if cfg.source != plugincfg.SourceDefault {
			t.Fatalf("非法值不应改内存 source: %q", cfg.source)
		}
	}
}

// TestConfigSourcePrecedence §4：config.json > 环境变量 > 默认值。
func TestConfigSourcePrecedence(t *testing.T) {
	stateDir := t.TempDir()
	store := plugincfg.NewStore(stateDir)
	if err := store.Write(json.RawMessage(`{"default_backend":"ufw","ssh_ports":[22],"dry_run_default":false}`)); err != nil {
		t.Fatalf("写配置文件失败: %v", err)
	}
	t.Setenv(EnvDefaultBackend, "iptables")
	values, source, err := resolveValues(store)
	if err != nil {
		t.Fatalf("解析配置失败: %v", err)
	}
	if source != plugincfg.SourceFile || values.DefaultBackend != "ufw" {
		t.Fatalf("文件优先级错误: source=%q backend=%q", source, values.DefaultBackend)
	}
}

// TestConfigSchemaNoSensitiveFields G-30：本仓无凭据类字段，
// config.get 不得回传任何 password/token/secret 字段，也不得出现明文凭据占位之外的敏感键。
func TestConfigSchemaNoSensitiveFields(t *testing.T) {
	cfg, fw := newConfigFixture(t)
	resp := configRequest(t, cfg, fw, "firewall.config.get", "")
	text := string(resp.Result)
	for _, needle := range []string{`"password"`, `"token"`, `"secret"`, "MYSQL_PWD=", "REDISCLI_AUTH="} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(needle)) {
			t.Fatalf("config.get 含敏感键/明文凭据 %q: %s", needle, text)
		}
	}
}

// TestInfoDeclaresConfigMethods：info.json 声明两条 config 方法及正确能力分级。
func TestInfoDeclaresConfigMethods(t *testing.T) {
	raw, err := os.ReadFile("info.json")
	if err != nil {
		t.Fatalf("读取 info.json 失败: %v", err)
	}
	var info struct {
		MethodCapabilities map[string]string `json:"method_capabilities"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("解析 info.json 失败: %v", err)
	}
	if got := info.MethodCapabilities["firewall.config.get"]; got != "system:read" {
		t.Fatalf("firewall.config.get 能力=%q，期望 system:read", got)
	}
	if got := info.MethodCapabilities["firewall.config.set"]; got != "system:admin" {
		t.Fatalf("firewall.config.set 能力=%q，期望 system:admin", got)
	}
}

// TestConfigFilePath §3：配置文件路径为 <KORE_STATE_DIR>/config.json。
func TestConfigFilePath(t *testing.T) {
	cfg, _ := newConfigFixture(t)
	want := filepath.Join(cfg.stateDir, "config.json")
	if cfg.store.Path() != want {
		t.Fatalf("配置文件路径=%q，期望 %q", cfg.store.Path(), want)
	}
}
