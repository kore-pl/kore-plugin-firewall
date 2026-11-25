> 状态: brouillon (草稿) · 归属: wave1 · 更新: 2026-11-25 · 里程碑: M5

# kore-plugin-firewall

Ce dépôt implémente le plugin de gestion du firewall/ports pour kore (id `firewall`). Ordre de détection : ufw → iptables → none (chemins fixes). Les écritures passent par SSH, listes blanches et dry-run ; les listes IP et bannissements anti-force brute sont appliqués via le proxy root-action du noyau — le plugin n’élève jamais ses privilèges et ne touche pas aux vraies règles du firewall hôte.

语言：[简体中文](DETAIL.md) · [English](DETAIL.en.md) · [Español](DETAIL.es.md) · [Français](DETAIL.fr.md) · [Deutsch](DETAIL.de.md) · [Русский](DETAIL.ru.md) · [Português](DETAIL.pt.md)

## Ce que fait le projet

- **Protocole** : `kore.plugin.v1`, `lifecycle=lazy`, capacité `system:admin`.
- **Méthodes** : `firewall.status` / `rules` / `allowPort` / `denyPort` / `deleteRule` / `ipList` / `ipAllow` / `ipDeny` / `ipRemove` / `recordFail` / `bruteSet` ; verbes nus acceptés.
- **Sondage réel** : `status` indique backend, disponibilité, état, politique par défaut et nombre de règles ; `rules` renvoie la vraie liste.
- **argv fixe** : uniquement `ufw` / `iptables` avec arguments fixes — pas de shell, pas d’accès à la configuration hôte.
- **Anti-force brute** : seuil configurable (5 échecs → bannissement de 10 min) ; bannissements temporaires automatiques, zéro minuteur dans le plugin.
- **Fail-closed** : sans root ni canal root-action, les écritures IP renvoient `E_NEED_ROOT` avec une piste actionnable.

## Démarrage rapide

```bash
make check    # gofmt → vet → test
make build    # compiler le binaire
make dist     # produire le tarball
```

Le plugin est lancé à la demande par le shell kore ; `info.json` déclare les capacités et `requires_kore`.

## Sécurité et limites

Signalez les vulnérabilités via [SECURITY.md](../SECURITY.md)

## Plan de la documentation

[SECURITY.md](../SECURITY.md) — procédure de divulgation.
[CONTRIBUTING.md](../CONTRIBUTING.md) — conventions de commit et version.
[CHANGELOG.md](../CHANGELOG.md) — historique.
[info.json](../info.json) — capacités et version.

## Questions fréquentes

**Q : Faut-il un compte ?**
Non. Pas de compte, de vérification en ligne ni de télémétrie cachée ; configuration en texte brut.

**Q : Où sont les plugins ?**
Chaque plugin a son propre dépôt `kore-plugin-<id>` et ne dépend que de `kore/pkg/pluginapi`.

**Q : Par où commencer ?**
Lisez le protocole et le tableau des méthodes du README, puis les capacités dans `info.json`.
