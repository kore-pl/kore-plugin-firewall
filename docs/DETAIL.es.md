> 状态: borrador (草稿) · 归属: wave1 · 更新: 2026-11-25 · 里程碑: M5

# kore-plugin-firewall

Este repositorio implementa el plugin de firewall/gestión de puertos de kore (id `firewall`). Prioridad de detección: ufw → iptables → none (rutas fijas). Las escrituras usan SSH, listas blancas y dry-run; las listas de IP y bloqueos por fuerza bruta se aplican mediante el proxy root-action del núcleo: el plugin no escala privilegios ni toca las reglas reales del firewall del host.

语言：[简体中文](DETAIL.md) · [English](DETAIL.en.md) · [Español](DETAIL.es.md) · [Français](DETAIL.fr.md) · [Deutsch](DETAIL.de.md) · [Русский](DETAIL.ru.md) · [Português](DETAIL.pt.md)

## Qué hace

- **Protocolo**: `kore.plugin.v1`, `lifecycle=lazy`, capacidad `system:admin`.
- **Métodos**: `firewall.status` / `rules` / `allowPort` / `denyPort` / `deleteRule` / `ipList` / `ipAllow` / `ipDeny` / `ipRemove` / `recordFail` / `bruteSet`; verbos simples aceptados.
- **Detección real**: `status` informa backend, disponibilidad, estado, política por defecto y número de reglas; `rules` devuelve la lista real.
- **argv fijo**: solo `ufw` / `iptables` con argumentos fijos; sin shell ni acceso a configuración del host.
- **Fuerza bruta**: umbral configurable (5 fallos → bloqueo de 10 min); bloqueos temporales automáticos, sin temporizadores en el plugin.
- **Fail-closed**: sin root ni canal root-action, las escrituras IP devuelven `E_NEED_ROOT` con pista accionable.

## Inicio rápido

```bash
make check    # gofmt → vet → test
make build    # compilar el binario
make dist     # generar el tarball
```

El plugin lo inicia el shell de kore bajo demanda; `info.json` declara capacidades y `requires_kore`.

## Seguridad y límites

Informa de vulnerabilidades por [SECURITY.md](../SECURITY.md)

## Mapa de documentación

[SECURITY.md](../SECURITY.md) — proceso de divulgación.
[CONTRIBUTING.md](../CONTRIBUTING.md) — convenciones de commit y versión.
[CHANGELOG.md](../CHANGELOG.md) — historial.
[info.json](../info.json) — capacidades y versión.

## Preguntas frecuentes

**P: ¿Necesito una cuenta?**
No. Sin cuentas, verificación en línea ni telemetría oculta; configuración en texto plano.

**P: ¿Dónde están los plugins?**
Cada plugin vive en su propio repositorio `kore-plugin-<id>` y solo depende de `kore/pkg/pluginapi`.

**P: ¿Por dónde empezar?**
Lee el protocolo y la tabla de métodos del README y luego las capacidades en `info.json`.
