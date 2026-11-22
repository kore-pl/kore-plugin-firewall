package fwop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// commandTimeout 是单次外部命令的上限；防火墙命令都是本地短命令，10s 足够。
const commandTimeout = 10 * time.Second

// Runner 执行一个固定 argv 命令并返回 stdout / stderr。
// 真实实现是 execRunner；测试注入 fixture / 故障 Runner，不接触宿主防火墙。
type Runner interface {
	Run(argv []string) (stdout, stderr []byte, err error)
}

// Policy 是调用方能力与 SSH 保护端口集合。
type Policy struct {
	Capabilities []string
	SSHPorts     []int
}

// canAdmin 判断策略是否携带 system:admin 能力。
func (p Policy) canAdmin() bool {
	for _, capability := range p.Capabilities {
		if capability == CapabilityAdmin {
			return true
		}
	}
	return false
}

// Options 是 Runtime 的构造参数；Runner / Resolve 留空时使用真实实现。
type Options struct {
	Capabilities []string
	SSHPorts     []int
	Runner       Runner
	Resolve      func(name string) (path string, ok bool)
}

// Runtime 是防火墙方法的执行面：探测后端、解析规则、执行 ufw 写操作。
type Runtime struct {
	runner  Runner
	resolve func(name string) (path string, ok bool)
	policy  Policy
}

// New 构造执行面并校验 SSH 保护端口；非法端口在启动期失败，不静默降级。
func New(opts Options) (*Runtime, error) {
	sshPorts, err := normalizeSSHPorts(opts.SSHPorts)
	if err != nil {
		return nil, err
	}
	runner := opts.Runner
	if runner == nil {
		runner = execRunner{}
	}
	resolve := opts.Resolve
	if resolve == nil {
		resolve = resolveBinary
	}
	return &Runtime{
		runner:  runner,
		resolve: resolve,
		policy: Policy{
			Capabilities: append([]string(nil), opts.Capabilities...),
			SSHPorts:     sshPorts,
		},
	}, nil
}

// SSHPorts 返回受保护的 SSH 端口集合（只读副本）。
func (r *Runtime) SSHPorts() []int {
	return append([]int(nil), r.policy.SSHPorts...)
}

// execRunner 是本机真实命令执行器：固定 argv、无 shell、C locale、带超时。
type execRunner struct{}

// Run 执行 argv[0] 与固定参数；环境强制 LC_ALL=C，保证解析不受宿主语言影响。
func (execRunner) Run(argv []string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Env = commandEnv(os.Environ())
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("命令超时（%s）", commandTimeout)
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

// commandEnv 覆盖 locale 为 C，避免 ufw / iptables 输出被本地化后解析失败。
func commandEnv(base []string) []string {
	env := make([]string, 0, len(base)+2)
	for _, item := range base {
		if strings.HasPrefix(item, "LC_ALL=") || strings.HasPrefix(item, "LANG=") {
			continue
		}
		env = append(env, item)
	}
	return append(env, "LC_ALL=C", "LANG=C")
}

// binaryCandidates 是已知安装路径；不依赖插件进程的 PATH（systemd 下常被裁剪）。
var binaryCandidates = map[string][]string{
	BackendUFW:      {"/usr/sbin/ufw", "/sbin/ufw", "/usr/bin/ufw", "/usr/local/sbin/ufw"},
	BackendIptables: {"/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables", "/usr/local/sbin/iptables"},
}

// resolveBinary 按固定候选路径探测后端二进制，最后回退 PATH 查找。
func resolveBinary(name string) (string, bool) {
	for _, path := range binaryCandidates[name] {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path, true
		}
	}
	if path, err := exec.LookPath(name); err == nil {
		return path, true
	}
	return "", false
}

// detect 按 ufw > iptables > none 优先级返回后端。
func (r *Runtime) detect() string {
	if _, ok := r.resolve(BackendUFW); ok {
		return BackendUFW
	}
	if _, ok := r.resolve(BackendIptables); ok {
		return BackendIptables
	}
	return BackendNone
}

// run 执行命令并把失败归一为可分类错误；故障注入/执行面已分类错误原样透传。
func (r *Runtime) run(argv []string) ([]byte, error) {
	stdout, stderr, err := r.runner.Run(argv)
	if err != nil {
		var fe *FaultError
		if errors.As(err, &fe) {
			return nil, err
		}
		var oe *OpError
		if errors.As(err, &oe) {
			return nil, err
		}
		return nil, commandError(argv, stderr, err)
	}
	return stdout, nil
}

// commandError 把命令失败分类为权限 / 上游错误，保留原始 stderr 便于定位。
func commandError(argv []string, stderr []byte, err error) error {
	detail := strings.TrimSpace(string(stderr))
	if detail == "" {
		detail = err.Error()
	}
	command := strings.Join(argv, " ")
	if isPermissionDetail(detail) {
		return opErr(ErrKindPermission, "执行 `%s` 失败: %s（插件需要 root 权限才能读取/修改防火墙）", command, detail)
	}
	return opErr(ErrKindUpstream, "执行 `%s` 失败: %s", command, detail)
}

// isPermissionDetail 识别权限类失败。命令统一以 LC_ALL=C 执行，故关键词稳定为英文；
// 同时保留中文兜底，避免宿主 locale 变更时误分类。
func isPermissionDetail(detail string) bool {
	lower := strings.ToLower(detail)
	needles := []string{
		"you must be root",
		"need to be root",
		"permission denied",
		"operation not permitted",
		"only root",
		"只有 root",
	}
	for _, needle := range needles {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}
