> 状态: rascunho (草稿) · 归属: wave1 · 更新: 2026-11-25 · 里程碑: M5

# kore-plugin-firewall

Este repositório implementa o plugin de gestão de firewall/portas do kore (id `firewall`). Ordem de detecção: ufw → iptables → none (caminhos fixos). Gravações usam SSH, allowlist e dry-run; listas de IP e bloqueios por força bruta são aplicados pelo proxy root-action do núcleo — o plugin nunca eleva privilégios nem toca nas regras reais do firewall do host.

语言：[简体中文](DETAIL.md) · [English](DETAIL.en.md) · [Español](DETAIL.es.md) · [Français](DETAIL.fr.md) · [Deutsch](DETAIL.de.md) · [Русский](DETAIL.ru.md) · [Português](DETAIL.pt.md)

## O que faz

- **Protocolo**: `kore.plugin.v1`, `lifecycle=lazy`, capacidade `system:admin`.
- **Métodos**: `firewall.status` / `rules` / `allowPort` / `denyPort` / `deleteRule` / `ipList` / `ipAllow` / `ipDeny` / `ipRemove` / `recordFail` / `bruteSet`; verbos simples aceitos.
- **Detecção real**: `status` informa backend, disponibilidade, estado, política padrão e número de regras; `rules` retorna a lista real.
- **argv fixo**: apenas `ufw` / `iptables` com argumentos fixos — sem shell nem acesso à configuração do host.
- **Força bruta**: limite configurável (5 falhas → bloqueio de 10 min); bloqueios temporários automáticos, zero timers no plugin.
- **Fail-closed**: sem root ou canal root-action, gravações de IP retornam `E_NEED_ROOT` com dica acionável.

## Início rápido

```bash
make check    # gofmt → vet → test
make build    # compilar o binário
make dist     # gerar o tarball
```

O plugin é iniciado sob demanda pelo shell do kore; `info.json` declara capacidades e `requires_kore`.

## Segurança e limites

Relate vulnerabilidades por [SECURITY.md](../SECURITY.md)

## Mapa da documentação

[SECURITY.md](../SECURITY.md) — processo de divulgação.
[CONTRIBUTING.md](../CONTRIBUTING.md) — convenções de commit e versão.
[CHANGELOG.md](../CHANGELOG.md) — histórico.
[info.json](../info.json) — capacidades e versão.

## Perguntas frequentes

**P: Preciso de uma conta?**
Não. Sem contas, verificação online ou telemetria oculta; configuração em texto simples.

**P: Onde ficam os plugins?**
Cada plugin fica em `kore-plugin-<id>` e depende apenas de `kore/pkg/pluginapi`.

**P: Por onde começar?**
Leia o protocolo e a tabela de métodos no README e depois as capacidades em `info.json`.
