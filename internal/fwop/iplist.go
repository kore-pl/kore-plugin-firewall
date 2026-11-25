package fwop

// 本文件实现 IP 白名单/黑名单与防爆破（竞品清单条目 5）。
//
// 数据面：kore 自有 nft 表 kore_fw，集合 allow4（白名单）、deny4（黑名单 + 防爆破
// 临时封禁，元素可带 timeout）；base chain input 上放「白名单 accept → 黑名单/封禁
// drop」两条规则，白名单优先避免误封。IPv6 不在本期范围（root_actions 上限 16 条），
// 见 README「已知边界」。
//
// 走 ADR-0018 root-action 通道：插件自身永不提权、不直接改宿主防火墙。
// 非 root 且通道不可用 → E_NEED_ROOT + 可操作 hint（fail-closed，绝不静默成功）。
// 无 ticker：临时封禁由 nft 集合元素 timeout 自动过期；state 仅作审计视图，
// 过期项在 list 读取时按 expires_at 惰性标记 expired。

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	nftTable = "kore_fw"
	nftChain = "input"
	// nftSetAllow / nftSetDeny 是 kore 自有集合：白名单 accept、黑名单（含临时封禁）drop。
	// 只建 IPv4 两个集合——root_actions 协议上限 16 条（ufw/iptables 已占 7 条），
	// 再拆 allow6/deny6 及各自的增删动作就装不下；IPv6 边界见 README「已知边界」。
	nftSetAllow = "allow4"
	nftSetDeny  = "deny4"
	iplistFile  = "iplist.json"

	DefaultBruteThreshold = 5
	DefaultBruteBanMin    = 10
	maxBruteThreshold     = 1000
	maxBruteBanMin        = 1440
	maxIPRules            = 500
	maxIPRunes            = 64
)

type IPMode string

const (
	IPModeAllow IPMode = "allow"
	IPModeDeny  IPMode = "deny"
	IPModeBan   IPMode = "ban"
)

type IPRule struct {
	ID        string `json:"id"`
	Mode      IPMode `json:"mode"`
	IP        string `json:"ip"`
	Comment   string `json:"comment,omitempty"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Expired   bool   `json:"expired,omitempty"`
}

type BruteConfig struct {
	Enabled   bool `json:"enabled"`
	Threshold int  `json:"threshold"`
	BanMin    int  `json:"ban_min"`
}

type IPListResult struct {
	Rules   []IPRule    `json:"rules"`
	Count   int         `json:"count"`
	Brute   BruteConfig `json:"brute"`
	Backend string      `json:"backend"`
	Error   string      `json:"error,omitempty"`
}

type IPWriteResult struct {
	Applied bool     `json:"applied"`
	DryRun  bool     `json:"dry_run"`
	Command []string `json:"command"`
	Rule    IPRule   `json:"rule"`
	// Note 如实说明「部分生效」的边界（如元素已不在宿主侧，只清理了 kore 记录）。
	Note string `json:"note,omitempty"`
}

type IPFailResult struct {
	IP        string `json:"ip"`
	Failures  int    `json:"failures"`
	Banned    bool   `json:"banned"`
	BanUntil  string `json:"ban_until,omitempty"`
	Threshold int    `json:"threshold"`
}

type (
	ipAddParams struct {
		Mode    string `json:"mode"`
		IP      string `json:"ip"`
		Comment string `json:"comment,omitempty"`
		DryRun  *bool  `json:"dry_run,omitempty"`
	}
	ipRemoveParams struct {
		ID     string `json:"id"`
		DryRun *bool  `json:"dry_run,omitempty"`
	}
	ipListParams struct{}
	ipFailParams struct {
		IP string `json:"ip"`
	}
	bruteSetParams struct {
		Enabled   *bool `json:"enabled,omitempty"`
		Threshold *int  `json:"threshold,omitempty"`
		BanMin    *int  `json:"ban_min,omitempty"`
	}
)

type persistedIPState struct {
	Rules      []IPRule       `json:"rules"`
	Brute      BruteConfig    `json:"brute"`
	FailCounts map[string]int `json:"fail_counts"`
}

type iplistStore struct {
	mu       sync.RWMutex
	path     string
	state    persistedIPState
	failSeen map[string]time.Time
	// readyMu / ready 缓存「kore 自有 nft 表已就绪」的探测结果，避免每次写都探活；
	// 插件进程重启后重新探活（表是运行态，宿主重启即消失）。
	readyMu sync.Mutex
	ready   bool
}

func newIPListStore(stateDir string) *iplistStore {
	s := &iplistStore{
		path:     filepath.Join(stateDir, iplistFile),
		failSeen: map[string]time.Time{},
		state: persistedIPState{
			Rules:      []IPRule{},
			Brute:      BruteConfig{Enabled: false, Threshold: DefaultBruteThreshold, BanMin: DefaultBruteBanMin},
			FailCounts: map[string]int{},
		},
	}
	if raw, err := os.ReadFile(s.path); err == nil {
		var loaded persistedIPState
		if err := json.Unmarshal(raw, &loaded); err == nil {
			if loaded.Rules != nil {
				s.state.Rules = loaded.Rules
			}
			if loaded.Brute.Threshold > 0 {
				s.state.Brute.Threshold = loaded.Brute.Threshold
			}
			if loaded.Brute.BanMin > 0 {
				s.state.Brute.BanMin = loaded.Brute.BanMin
			}
			s.state.Brute.Enabled = loaded.Brute.Enabled
			if loaded.FailCounts != nil {
				s.state.FailCounts = loaded.FailCounts
			}
		}
	}
	return s
}

func (s *iplistStore) save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.saveLocked()
}

// saveLocked 在调用方已持有 mu 时写盘，不重复加锁（供持写锁的 setBrute 调用）。
func (s *iplistStore) saveLocked() error {
	if strings.TrimSpace(filepath.Dir(s.path)) == "." || s.path == iplistFile {
		return errors.New("KORE_STATE_DIR 未设置，无法保存 IP 名单")
	}
	payload, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".iplist-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.path); err != nil {
		return err
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}

func (s *iplistStore) snapshot() IPListResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	rules := make([]IPRule, 0, len(s.state.Rules))
	for _, r := range s.state.Rules {
		if r.Mode == IPModeBan && r.ExpiresAt != "" {
			if expiry, err := time.Parse(time.RFC3339, r.ExpiresAt); err == nil && now.After(expiry) {
				r.Expired = true
			}
		}
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].CreatedAt < rules[j].CreatedAt })
	return IPListResult{Rules: rules, Count: len(rules), Brute: s.state.Brute}
}

// normalizeIP 校验 IPv4/CIDR：字符集只允许 0-9 a-f A-F . : /（无主机名、无注入字符），
// 并拒绝 IPv6（kore 自有 nft 集合只建 IPv4 两个，原因见 nftSetAllow 注释）。
func normalizeIP(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > maxIPRunes {
		return "", opErr(ErrKindInvalid, "ip 不能为空且不超过 %d 个字符", maxIPRunes)
	}
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == '.' || r == ':' || r == '/' {
			continue
		}
		return "", opErr(ErrKindInvalid, "ip 必须是 IPv4 地址或网段（如 203.0.113.7 / 10.0.0.0/8）")
	}
	if strings.Contains(value, ":") {
		return "", opErr(ErrKindUnsupported,
			"IP 名单当前只支持 IPv4：IPv6 请先用 ufw 规则（ufw allow from 2001:db8::1 或 ufw deny from …）")
	}
	if strings.Contains(value, "/") {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return "", opErr(ErrKindInvalid, "网段不合法（如 10.0.0.0/8）：%s", value)
		}
		if network.IP.To4() == nil {
			return "", opErr(ErrKindUnsupported, "IP 名单当前只支持 IPv4 网段")
		}
		if network.String() != value {
			// 归一化（如 10.1.2.3/8 → 10.0.0.0/8），保持状态里存的值即内核实际生效的值。
			return network.String(), nil
		}
		return network.String(), nil
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return "", opErr(ErrKindInvalid, "ip 必须是合法 IPv4 地址（如 203.0.113.7）")
	}
	return ip.String(), nil
}

// nft root-action 的 6 个动作（root_actions 协议上限 16 条，ufw/iptables 已占 7 条）。
//
// 设计要点：root-action 的声明 argv 就是 exec argv（不经 shell），而 nft 自己把 argv
// 用空格拼成一行再做词法分析，所以「一条 nft 语句」可以写成单个含空格的 argv 元素，
// 多条语句用独立的 ";" 元素分隔（内核 rootpolicy 按顶层 ";" 切语句，单动作 ≤8 句）。
// 这样建表 + 建两个集合 + base chain + 两条链规则能压进 1 个动作，省下名额给元素增删。
// 元素增删必须按集合各立一条动作：内核 nft 形状表的 "add element" 语句是
// <add element inet kore_fw <集合>> 五段 token，集合名写死在声明 argv 里，
// 追加参数只能是 { <ip> [timeout Ns] }，所以不能用一个动作 + 追加集合名。
const (
	nftActionList   = "nft-list"
	nftActionInit   = "nft-init"
	nftActionAddOK  = "nft-add-allow4"
	nftActionDelOK  = "nft-del-allow4"
	nftActionAddBad = "nft-add-deny4"
	nftActionDelBad = "nft-del-deny4"
)

// nftOp 是一次 nft 执行：root-action id + 追加参数 + 直连 argv（插件以 root 运行时用）。
type nftOp struct {
	action string
	args   []string
	argv   []string
}

// nftListOp 探活 kore 自有表：表存在 → 退出码 0；不存在/无权限 → 非零。
func nftListOp() nftOp {
	return nftOp{action: nftActionList, argv: []string{"list", "table", "inet", nftTable}}
}

// nftInitOp 建表 + 集合 allow4/deny4 + input base chain + 链规则（白名单 accept 先于 deny drop）。
//
// 6 条语句：add table / add set allow4 / add set deny4 / add chain / add rule allow4 /
// add rule deny4。nft 的 add 不幂等（对象已存在即失败），所以只在探活失败时下发。
func nftInitOp() nftOp {
	return nftOp{
		action: nftActionInit,
		argv: []string{
			"add table inet " + nftTable,
			";",
			"add set inet " + nftTable + " " + nftSetAllow + " { type ipv4_addr ; flags interval ; }",
			";",
			"add set inet " + nftTable + " " + nftSetDeny + " { type ipv4_addr ; flags interval,timeout ; }",
			";",
			"add chain inet " + nftTable + " " + nftChain + " { type filter hook input priority -10 ; policy accept ; }",
			";",
			"add rule inet " + nftTable + " " + nftChain + " ip saddr @" + nftSetAllow + " counter accept",
			";",
			"add rule inet " + nftTable + " " + nftChain + " ip saddr @" + nftSetDeny + " counter drop",
		},
	}
}

// nftElementOp 构造元素增删动作：白名单进 allow4，黑名单与临时封禁共用 deny4
// （封禁 = 带 timeout 的黑名单元素，到期由内核超时自动移除，插件零 ticker）。
//
// 追加参数逐位是 { <ip> [timeout Ns] }，由内核 rootpolicy 的 nft 形状表逐位校验
// （禁 ";"、引号、换行，因此追加参数拼不出第二条语句）。
func nftElementOp(verb string, mode IPMode, ip string, ttl int) nftOp {
	set, action := nftSetDeny, nftActionAddBad
	if mode == IPModeAllow {
		set, action = nftSetAllow, nftActionAddOK
	}
	if verb == "delete" {
		if mode == IPModeAllow {
			action = nftActionDelOK
		} else {
			action = nftActionDelBad
		}
	}
	args := []string{"{", ip}
	if ttl > 0 {
		args = append(args, "timeout", strconv.Itoa(ttl)+"s")
	}
	args = append(args, "}")
	argv := append([]string{verb + " element inet " + nftTable + " " + set}, args...)
	return nftOp{action: action, args: args, argv: argv}
}

// nftExecute 执行一次 nft 动作：root 直跑；否则必须经内核 root-action 通道（fail-closed）。
func (r *Runtime) nftExecute(op nftOp) ([]byte, error) {
	if isRoot() {
		path, ok := r.resolve("nft")
		if !ok {
			return nil, opErr(ErrKindUnsupported, "未检测到 nft 命令：IP 名单需要 nftables（apt install nftables 后重试）")
		}
		return r.run(append([]string{path}, op.argv...))
	}
	if r.rootAction == nil {
		return nil, opErr(ErrKindPermission, "非 root 且内核 root-action 通道不可用，无法下发 %s", op.action)
	}
	out, code, err := r.rootAction(op.action, op.args)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return out, opErr(ErrKindUpstream, "root-action %s 退出码 %d：%s", op.action, code, nftDiagnostic(out))
	}
	return out, nil
}

// nftDiagnostic 把 nft 的报错压成一行（最多 200 字符），进错误信息给用户看。
func nftDiagnostic(out []byte) string {
	text := strings.TrimSpace(string(out))
	text = strings.ReplaceAll(text, "\n", "; ")
	if text == "" {
		return "（无输出）"
	}
	runes := []rune(text)
	if len(runes) > 200 {
		return string(runes[:200]) + "…"
	}
	return text
}

// ensureNftTable 保证 kore 自有表可用，并在「表是新建的」时回灌持久化规则。
//
// 探活失败不直接报错：表缺失、nft 未安装、非 root 无权限都会让 list 非零，
// 用 init 的结果判定，避免把「表不存在」误报成权限问题（或反之自欺）。
func (r *Runtime) ensureNftTable() error {
	store := r.iplist
	if store == nil {
		return opErr(ErrKindInternal, "IP 名单状态未装配")
	}
	store.readyMu.Lock()
	defer store.readyMu.Unlock()
	if store.ready {
		return nil
	}
	if _, err := r.nftExecute(nftListOp()); err == nil {
		store.ready = true
		return nil
	}
	if _, err := r.nftExecute(nftInitOp()); err != nil {
		// init 失败可能只是「表已存在」（add 不幂等）：再探活一次确认，探活也失败才报错。
		if _, probeErr := r.nftExecute(nftListOp()); probeErr != nil {
			return err
		}
		store.ready = true
		return nil
	}
	store.ready = true
	// 表刚建出来：宿主侧规则为空，按持久化状态回灌，避免「界面有、宿主没有」的静默分叉。
	return r.reconcileIPRules()
}

// reconcileIPRules 把状态里的规则重新下发到（新建的）nft 表；过期封禁直接跳过。
func (r *Runtime) reconcileIPRules() error {
	store := r.iplist
	store.mu.RLock()
	rules := append([]IPRule(nil), store.state.Rules...)
	store.mu.RUnlock()
	now := time.Now()
	failed := 0
	var firstErr error
	for _, rule := range rules {
		ttl := 0
		if rule.Mode == IPModeBan && rule.ExpiresAt != "" {
			expiry, err := time.Parse(time.RFC3339, rule.ExpiresAt)
			if err == nil && !now.Before(expiry) {
				continue // 已过期：nft 里本来就不该存在
			}
			if err == nil {
				ttl = int(expiry.Sub(now).Seconds())
				if ttl < 1 {
					ttl = 1
				}
			}
		}
		if _, err := r.nftExecute(nftElementOp("add", rule.Mode, rule.IP, ttl)); err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if failed > 0 {
		return opErr(ErrKindUpstream, "已重建 nft 表，但回灌 %d 条规则失败（首个错误：%v）；请重新添加这些规则", failed, firstErr)
	}
	return nil
}

// addIP 添加白/黑/封禁规则；写操作要求 system:admin 且必须经 root-action 通道。
func (r *Runtime) addIP(params ipAddParams) (IPWriteResult, error) {
	mode := IPMode(strings.ToLower(strings.TrimSpace(params.Mode)))
	if mode != IPModeAllow && mode != IPModeDeny && mode != IPModeBan {
		return IPWriteResult{}, opErr(ErrKindInvalid, "mode 必须是 allow/deny/ban")
	}
	ip, ierr := normalizeIP(params.IP)
	if ierr != nil {
		return IPWriteResult{}, ierr
	}
	if perr := validateComment(params.Comment); perr != nil {
		return IPWriteResult{}, opErr(ErrKindInvalid, "%s", perr.Message)
	}
	store := r.iplist
	if store == nil {
		return IPWriteResult{}, opErr(ErrKindInternal, "IP 名单状态未装配")
	}
	snap := store.snapshot()
	if len(snap.Rules) >= maxIPRules {
		return IPWriteResult{}, opErr(ErrKindInvalid, "IP 规则已达上限 %d 条，请先删除不再需要的规则", maxIPRules)
	}
	now := time.Now()
	rule := IPRule{ID: fmt.Sprintf("ip-%d", now.UnixNano()), Mode: mode, IP: ip,
		Comment: strings.TrimSpace(params.Comment), CreatedAt: now.UTC().Format(time.RFC3339)}
	if mode == IPModeBan {
		rule.ExpiresAt = now.Add(time.Duration(snap.Brute.BanMin) * time.Minute).UTC().Format(time.RFC3339)
	}
	ttl := 0
	if mode == IPModeBan {
		ttl = snap.Brute.BanMin * 60
	}
	op := nftElementOp("add", mode, ip, ttl)
	result := IPWriteResult{Command: append([]string{"nft"}, op.argv...), Rule: rule}
	if r.effectiveDryRun(params.DryRun) {
		result.DryRun = true
		return result, nil
	}
	if err := r.ensureNftTable(); err != nil {
		return IPWriteResult{}, err
	}
	if _, err := r.nftExecute(op); err != nil {
		return IPWriteResult{}, err
	}
	store.mu.Lock()
	store.state.Rules = append(store.state.Rules, rule)
	store.mu.Unlock()
	if err := store.save(); err != nil {
		return IPWriteResult{}, opErr(ErrKindInternal, "规则已下发但保存状态失败：%v", err)
	}
	result.Applied = true
	return result, nil
}

// removeIP 按 id 删除规则并同步移除 nft 集合元素。
func (r *Runtime) removeIP(params ipRemoveParams) (IPWriteResult, error) {
	store := r.iplist
	if store == nil {
		return IPWriteResult{}, opErr(ErrKindInternal, "IP 名单状态未装配")
	}
	store.mu.RLock()
	var target IPRule
	found := false
	for _, rule := range store.state.Rules {
		if rule.ID == params.ID {
			target, found = rule, true
			break
		}
	}
	store.mu.RUnlock()
	if !found {
		return IPWriteResult{}, opErr(ErrKindNotFound, "规则 %s 不存在", params.ID)
	}
	op := nftElementOp("delete", target.Mode, target.IP, 0)
	result := IPWriteResult{Command: append([]string{"nft"}, op.argv...), Rule: target}
	if r.effectiveDryRun(params.DryRun) {
		result.DryRun = true
		return result, nil
	}
	if err := r.ensureNftTable(); err != nil {
		return IPWriteResult{}, err
	}
	if _, err := r.nftExecute(op); err != nil {
		// 元素已不在宿主侧（宿主重启后表被重建）：删除是「减少封禁」的安全方向，
		// 仍清理 kore 记录，但 applied=false + note 如实说明未真正下发，绝不谎报成功。
		var oe *OpError
		if !errors.As(err, &oe) || oe.Kind != ErrKindUpstream {
			return IPWriteResult{}, err
		}
		result.Note = "nft 中未找到该元素（表可能已重建），已只清理 kore 记录：" + oe.Message
	} else {
		result.Applied = true
	}
	store.mu.Lock()
	kept := store.state.Rules[:0]
	for _, rule := range store.state.Rules {
		if rule.ID != params.ID {
			kept = append(kept, rule)
		}
	}
	store.state.Rules = kept
	store.mu.Unlock()
	if err := store.save(); err != nil {
		return IPWriteResult{}, opErr(ErrKindInternal, "规则已移除但保存状态失败：%v", err)
	}
	return result, nil
}

// recordFail 记录一次登录失败；达阈值自动封禁（防爆破开启时）。
// 调用方负责传精确来源 IP——审计里的 IP 已脱敏，不能复用。
func (r *Runtime) recordFail(params ipFailParams) (IPFailResult, error) {
	ip, ierr := normalizeIP(params.IP)
	if ierr != nil {
		return IPFailResult{}, ierr
	}
	store := r.iplist
	if store == nil {
		return IPFailResult{}, opErr(ErrKindInternal, "IP 名单状态未装配")
	}
	cfg := store.snapshot().Brute
	result := IPFailResult{IP: ip, Threshold: cfg.Threshold}
	if !cfg.Enabled {
		return result, nil
	}
	now := time.Now()
	store.mu.Lock()
	if started, seen := store.failSeen[ip]; !seen || now.Sub(started) > 10*time.Minute {
		store.failSeen[ip] = now
		store.state.FailCounts[ip] = 0
	}
	store.state.FailCounts[ip]++
	result.Failures = store.state.FailCounts[ip]
	alreadyBanned := false
	for _, rule := range store.state.Rules {
		if rule.Mode == IPModeBan && rule.IP == ip {
			if rule.ExpiresAt == "" {
				alreadyBanned = true
			} else if expiry, err := time.Parse(time.RFC3339, rule.ExpiresAt); err == nil && now.Before(expiry) {
				alreadyBanned = true
			}
		}
	}
	store.mu.Unlock()
	_ = store.save()
	if alreadyBanned || result.Failures < cfg.Threshold {
		return result, nil
	}
	added, err := r.addIP(ipAddParams{Mode: string(IPModeBan), IP: ip, Comment: "防爆破自动封禁"})
	if err != nil {
		return result, err
	}
	result.Banned = added.Applied
	result.BanUntil = added.Rule.ExpiresAt
	store.mu.Lock()
	store.state.FailCounts[ip] = 0
	delete(store.failSeen, ip)
	store.mu.Unlock()
	_ = store.save()
	return result, nil
}

// setBrute 更新防爆破阈值与时长（热生效，持久化到状态文件）。
func (r *Runtime) setBrute(params bruteSetParams) (BruteConfig, error) {
	store := r.iplist
	if store == nil {
		return BruteConfig{}, opErr(ErrKindInternal, "IP 名单状态未装配")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if params.Enabled != nil {
		store.state.Brute.Enabled = *params.Enabled
	}
	if params.Threshold != nil {
		if *params.Threshold < 1 || *params.Threshold > maxBruteThreshold {
			return BruteConfig{}, opErr(ErrKindInvalid, "threshold 必须是 1-%d 的整数", maxBruteThreshold)
		}
		store.state.Brute.Threshold = *params.Threshold
	}
	if params.BanMin != nil {
		if *params.BanMin < 1 || *params.BanMin > maxBruteBanMin {
			return BruteConfig{}, opErr(ErrKindInvalid, "ban_min 必须是 1-%d 的分钟数", maxBruteBanMin)
		}
		store.state.Brute.BanMin = *params.BanMin
	}
	if err := store.saveLocked(); err != nil {
		return BruteConfig{}, opErr(ErrKindInternal, "保存防爆破配置失败：%v", err)
	}
	return store.state.Brute, nil
}

// listIP 返回当前规则与防爆破配置（只读；不触碰宿主防火墙）。
func (r *Runtime) listIP() (IPListResult, error) {
	store := r.iplist
	if store == nil {
		return IPListResult{}, opErr(ErrKindInternal, "IP 名单状态未装配")
	}
	result := store.snapshot()
	if _, ok := r.resolve("nft"); ok {
		result.Backend = "nft"
	} else {
		result.Backend = "none"
	}
	return result, nil
}
