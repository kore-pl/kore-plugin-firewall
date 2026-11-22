package fwop

import (
	"encoding/json"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// callAllowPort 处理 firewall.allowPort：校验端口与协议后返回结构化占位结果。
// 骨架口径下 applied=false，不真放行任何宿主端口。
func callAllowPort(raw json.RawMessage, exec Executor) (json.RawMessage, *pluginapi.Error) {
	var p allowPortParams
	if perr := decodeParams(raw, &p); perr != nil {
		return nil, perr
	}
	if perr := checkPort(p.Port); perr != nil {
		return nil, perr
	}
	if perr := checkProtocol(p.Protocol); perr != nil {
		return nil, perr
	}
	if _, err := exec.AllowPort(p.Port, p.Protocol); err != nil {
		return nil, classify(err)
	}
	return encode(AllowPortResult{
		Port: p.Port, Protocol: p.Protocol, Applied: false,
	})
}

// checkPort 校验端口在 1-65535 区间。
func checkPort(port int) *pluginapi.Error {
	if port < 1 || port > 65535 {
		return invalid("port 必须在 1-65535 之间")
	}
	return nil
}

// checkProtocol 校验协议只取 tcp/udp/icmp。
func checkProtocol(protocol string) *pluginapi.Error {
	switch protocol {
	case "tcp", "udp", "icmp":
		return nil
	}
	return invalid("protocol 必须是 tcp/udp/icmp")
}
