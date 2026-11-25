> 状态: Entwurf (草稿) · 归属: wave1 · 更新: 2026-11-25 · 里程碑: M5

# kore-plugin-firewall

Dieses Repository implementiert das Firewall-/Portverwaltungs-Plugin für Kore (id `firewall`). Erkennungsreihenfolge: ufw → iptables → none (feste Pfade). Schreibzugriffe nutzen SSH, Allowlists und dry-run; IP-Listen und Brute-Force-Sperren werden über den Kernel-root-action-Proxy gesetzt — das Plugin eskaliert nie Rechte und berührt keine echten Host-Firewallregeln.

语言：[简体中文](DETAIL.md) · [English](DETAIL.en.md) · [Español](DETAIL.es.md) · [Français](DETAIL.fr.md) · [Deutsch](DETAIL.de.md) · [Русский](DETAIL.ru.md) · [Português](DETAIL.pt.md)

## Was es tut

- **Protokoll**: `kore.plugin.v1`, `lifecycle=lazy`, Capability `system:admin`.
- **Methoden**: `firewall.status` / `rules` / `allowPort` / `denyPort` / `deleteRule` / `ipList` / `ipAllow` / `ipDeny` / `ipRemove` / `recordFail` / `bruteSet`; nackte Verben erlaubt.
- **Echte Erkennung**: `status` meldet Backend, Verfügbarkeit, Zustand, Standardrichtlinie und Regelzahl; `rules` liefert die echte Liste.
- **Festes argv**: nur `ufw` / `iptables` mit festen Argumenten — keine Shell, kein Zugriff auf Host-Konfiguration.
- **Brute-Force**: konfigurierbarer Schwellwert (5 Fehlversuche → 10-Minuten-Sperre); automatische temporäre Sperren, keine Timer im Plugin.
- **Fail-closed**: ohne Root oder Kernel-root-action-Kanal geben IP-Schreibzugriffe `E_NEED_ROOT` mit handlichem Hinweis zurück.

## Schnellstart

```bash
make check    # gofmt → vet → test
make build    # Plugin-Binary bauen
make dist     # Release-Tarball erzeugen
```

Das Plugin wird von der Kore-Shell bei Bedarf gestartet; `info.json` deklariert Capabilities und `requires_kore`.

## Sicherheit und Grenzen

Melde Schwachstellen über [SECURITY.md](../SECURITY.md)

## Dokumentationsübersicht

[SECURITY.md](../SECURITY.md) — Offenlegungsprozess.
[CONTRIBUTING.md](../CONTRIBUTING.md) — Commit- und Release-Konventionen.
[CHANGELOG.md](../CHANGELOG.md) — Versionshistorie.
[info.json](../info.json) — Capabilities und Version.

## Häufige Fragen

**F: Brauche ich ein Konto?**
Nein. Keine Konten, keine Online-Prüfung, keine Telemetrie; Konfiguration im Klartext.

**F: Wo liegen die Plugins?**
Jedes Plugin liegt in `kore-plugin-<id>` und hängt nur von `kore/pkg/pluginapi` ab.

**F: Wo anfangen?**
Lies Protokoll und Methodentabelle in der README, dann die Capabilities in `info.json`.
