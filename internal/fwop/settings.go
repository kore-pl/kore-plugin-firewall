package fwop

import (
	"fmt"
	"sync"
)

// 默认后端的枚举值：auto 表示自动探测（ufw > iptables > none），
// 与 selectBackend("") 的语义一致；显式值要求对应后端已安装。
const (
	BackendAuto = "auto"
)

// Settings 是可热更的运行期设置，对应 config 面板的三个真实能力字段：
//   - SSHPorts：denyPort / deleteRule 的 SSH 保护端口（始终含 22）；
//   - DefaultBackend：rules 未显式指定 backend 时使用的后端；
//   - DryRunDefault：写方法未显式指定 dry_run 时是否只返回命令不执行。
//
// 这些值在 config.set 成功后经 Runtime.UpdateSettings 立即生效，
// 下一次方法调用即读取新值，无需重启插件进程（PLUGIN-CONFIG §5）。
type Settings struct {
	SSHPorts       []int
	DefaultBackend string
	DryRunDefault  bool
}

// DefaultSettings 返回代码默认设置。
func DefaultSettings() Settings {
	return Settings{
		SSHPorts:       []int{DefaultSSHPort},
		DefaultBackend: BackendAuto,
		DryRunDefault:  false,
	}
}

// NormalizeSettings 校验并归一化设置；非法值在启动加载与 config.set 时共用。
func NormalizeSettings(s Settings) (Settings, error) {
	ports, err := normalizeSSHPorts(s.SSHPorts)
	if err != nil {
		return Settings{}, err
	}
	backend := s.DefaultBackend
	switch backend {
	case "", BackendAuto:
		backend = BackendAuto
	case BackendUFW, BackendIptables:
	default:
		return Settings{}, fmt.Errorf("default_backend=%q 非法：仅允许 auto/ufw/iptables", s.DefaultBackend)
	}
	return Settings{SSHPorts: ports, DefaultBackend: backend, DryRunDefault: s.DryRunDefault}, nil
}

// settingsState 是 Runtime 内受锁保护的设置与 SSH 护栏快照。
type settingsState struct {
	mu       sync.RWMutex
	settings Settings
}

// update 校验并替换设置，返回只读快照。
func (s *settingsState) update(next Settings) (Settings, error) {
	normalized, err := NormalizeSettings(next)
	if err != nil {
		return Settings{}, err
	}
	s.mu.Lock()
	s.settings = Settings{
		SSHPorts:       append([]int(nil), normalized.SSHPorts...),
		DefaultBackend: normalized.DefaultBackend,
		DryRunDefault:  normalized.DryRunDefault,
	}
	s.mu.Unlock()
	return s.snapshot(), nil
}

// snapshot 返回设置的只读副本（切片隔离，调用方修改不影响内部状态）。
func (s *settingsState) snapshot() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Settings{
		SSHPorts:       append([]int(nil), s.settings.SSHPorts...),
		DefaultBackend: s.settings.DefaultBackend,
		DryRunDefault:  s.settings.DryRunDefault,
	}
}

// sshPorts 返回受保护的 SSH 端口副本（护栏判定在锁内完成）。
func (s *settingsState) sshPorts() []int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]int(nil), s.settings.SSHPorts...)
}

// defaultBackend 返回 rules 缺省后端；auto 映射为空串以复用 selectBackend 的自动探测语义。
func (s *settingsState) defaultBackend() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.settings.DefaultBackend == BackendAuto {
		return ""
	}
	return s.settings.DefaultBackend
}

// dryRunDefault 返回写方法缺省 dry_run。
func (s *settingsState) dryRunDefault() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings.DryRunDefault
}
