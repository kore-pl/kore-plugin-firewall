# kore-plugin-firewall

防火墙/端口管理插件（**骨架**）：覆盖防火墙规则管理 / 端口放行的方法面。本仓只交付协议骨架与参数校验，**不真调用 iptables/nftables/firewalld、不内置任何工具二进制**；提案 §2.1 批3 约定「只改 `kore:` 段」（裁决 37）。

## 协议面

- `kore.plugin.v1`，`lifecycle=lazy`，`depth_level=production`
- 能力声明：`system:admin`
- 方法：`firewall.rules` / `firewall.allowPort`（同时接受裸 `rules` / `allowPort`）
- 握手的 stdout 留给协议帧，日志一律写 stderr

## 方法与参数（骨架口径）

- `firewall.rules`：`{"action":"list|add|remove","chain":"kore-input"}`（chain 可省略，缺省 `kore-input`，只含字母/数字/`-`/`_`/`:`，≤64 字符）
- `firewall.allowPort`：`{"port":1-65535,"protocol":"tcp|udp|icmp"}`
- 两者都返回结构化占位结果：`applied=false`（不真改宿主防火墙状态）
- 非法参数返回 `E_INVALID`；未知方法返回 `E_NOTFOUND`

## 四类故障注入

`tests/fault/` 四个文件分别注入 kill -9、超时、磁盘满、cgroup 超限，断言方法级返回结构化错误，且 `Error.Code` 与故障类别一一对应：

| 故障 | 文件 | 期望错误码 |
| --- | --- | --- |
| kill -9 | `kill_test.go` | `E_UPSTREAM` |
| 超时 | `timeout_test.go` | `E_UPSTREAM` |
| 磁盘满 | `disk_test.go` | `E_INTERNAL` |
| cgroup 超限 | `cgroup_test.go` | `E_UNSUPPORTED` |

会话测试中每个 `kore.shutdown` 请求都配对读回响应帧——`net.Pipe` 无缓冲，不读帧会导致写响应永久阻塞。

## 构建与验收

```bash
gofmt -l . && go vet ./... && go test -timeout 200s ./...
make build && make dist
tar -tzf dist/firewall-0.1.0.tar.gz | head -1   # info.json
```

`dist` 使用确定性参数归档，重复构建 sha256 不变；`size_bytes` 经不动点迭代回写到源 `info.json`，与实际包体偏差 ≤10%。
