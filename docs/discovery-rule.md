# Règle de découverte — capturer les vrais domaines (SNI) des flux SAP RISE

## Objectif

Les flux SSL sortants du segment SAP RISE qui ne matchent aucune catégorie URL
tombent sur `interzone-default` → **reset-both** (policy-deny). Le **SNI n'est
PAS loggé** sur ces deny (vérifié : champ `domain=0`, aucun champ SNI).

Cette règle **temporaire** autorise + **logge toutes les URL** du segment SAP RISE
en sortie 443, pour **capturer les vrais domaines** (SNI). Une fois la liste
obtenue, on bâtit la/les catégorie(s) URL custom définitives, on crée la règle
d'autorisation ciblée, et **on retire cette règle temporaire**.

> ⚠️ Règle **temporaire** et **permissive** (allow 443 sortant pour SAP RISE).
> À poser en connaissance de cause, idéalement sur une fenêtre courte, puis retirer.

---

## Contexte confirmé (depuis les logs)

| Élément | Valeur |
|---------|--------|
| Zones | `from Private` → `to Public` |
| Source (objets) | `SAP-RISE-10.120.0.0_22`, `SAP-RISE-10.120.4.0_22` |
| App / service | `ssl` / `application-default` |
| Déchiffrement | non (`s_decrypted=0`) |
| Device-group (règles SAP) | `cngfw-az-partnerhub` (ou `shared`) |

---

## Étape 1 — Profil URL filtering qui LOGGE tout

Il faut un profil URL filtering où **toutes les catégories sont en `alert`**
(= autorisé mais **loggé**) → c'est ce qui fait apparaître le SNI/URL dans les
**logs URL**.

**Le plus simple (GUI Panorama) :**
1. Objects → URL Filtering → cloner le profil **default**,
2. Le nommer `URL-Discovery-AlertAll`,
3. Sélectionner **toutes les catégories** → Action = **alert**,
4. (laisser le reste par défaut).

> En CLI il faudrait lister chaque catégorie (~75 lignes) — le clone GUI + "set
> all to alert" est bien plus rapide et fiable.

---

## Étape 2 — Règle de découverte (commandes `set`)

> Contexte **device-group** (adapter `cngfw-az-partnerhub` si besoin, ou utiliser
> `set shared pre-rulebase ...`). Placer **en haut** du pre-rulebase (au-dessus de
> tout block).

```
set device-group cngfw-az-partnerhub pre-rulebase security rules "TEMP-RISE-Discovery-443" from Private
set device-group cngfw-az-partnerhub pre-rulebase security rules "TEMP-RISE-Discovery-443" to Public
set device-group cngfw-az-partnerhub pre-rulebase security rules "TEMP-RISE-Discovery-443" source [ SAP-RISE-10.120.0.0_22 SAP-RISE-10.120.4.0_22 ]
set device-group cngfw-az-partnerhub pre-rulebase security rules "TEMP-RISE-Discovery-443" destination any
set device-group cngfw-az-partnerhub pre-rulebase security rules "TEMP-RISE-Discovery-443" application ssl
set device-group cngfw-az-partnerhub pre-rulebase security rules "TEMP-RISE-Discovery-443" service application-default
set device-group cngfw-az-partnerhub pre-rulebase security rules "TEMP-RISE-Discovery-443" action allow
set device-group cngfw-az-partnerhub pre-rulebase security rules "TEMP-RISE-Discovery-443" category any
set device-group cngfw-az-partnerhub pre-rulebase security rules "TEMP-RISE-Discovery-443" profile-setting profiles url-filtering URL-Discovery-AlertAll
set device-group cngfw-az-partnerhub pre-rulebase security rules "TEMP-RISE-Discovery-443" log-start no
set device-group cngfw-az-partnerhub pre-rulebase security rules "TEMP-RISE-Discovery-443" log-end yes
set device-group cngfw-az-partnerhub pre-rulebase security rules "TEMP-RISE-Discovery-443" description "TEMP - capture SNI flux SAP RISE 443 - A RETIRER"
```

Puis **commit + push** vers le device-group.

> 🔐 **No-decrypt** : cette règle n'active pas le déchiffrement (bien pour un
> client SAP non-navigateur). On capture le SNI depuis le ClientHello (pas besoin
> de déchiffrer).

---

## Étape 3 — Laisser tourner puis CAPTURER les domaines

Laisser quelques heures (les SAP re-tentent leurs flux), puis :

```bash
python scripts/diagnose_flow.py --src 10.120.0.0/22 --port 443 --discover --days 1 --nlogs 100
```

Cette fois les **logs URL contiennent les vrais domaines** (la règle les logge).
La section `[URL]` du rapport donnera la **liste exacte** des domaines contactés
(Microsoft, CloudFront-fronted, SAP, etc.).

---

## Étape 4 — Bâtir la policy définitive

À partir de la liste capturée, **regrouper par besoin** et créer des catégories
URL custom ciblées, par exemple :
- `RISE-Microsoft-Auth` : `login.microsoftonline.com`, `login.microsoft.com`,
  `login.windows.net`, `*.msauth.net`, `*.msftauth.net`, `sts.windows.net`, …
- `RISE-<autre-service>` : domaines CloudFront/Azure identifiés.

Puis une règle d'autorisation par besoin (design) :
```
from Private to Public
source SAP-RISE-10.120.0.0_22, SAP-RISE-10.120.4.0_22
destination any
application ssl
service application-default
category <RISE-Microsoft-Auth>
action allow
(profils: log + security standard ; NO-DECRYPT pour clients SAP)
```

---

## Étape 5 — RETIRER la règle de découverte

```
delete device-group cngfw-az-partnerhub pre-rulebase security rules "TEMP-RISE-Discovery-443"
```
Puis commit + push. (On peut garder le profil `URL-Discovery-AlertAll` pour un
usage futur, ou le supprimer.)

---

## Notes de sûreté

- Règle **temporaire** et permissive → fenêtre courte, puis retrait.
- Pas de déchiffrement activé (clients SAP non-navigateur OK).
- La règle finale doit être **ciblée par catégorie URL** (pas `destination any`
  en permanent, pas d'objet FQDN unique qui ne couvre pas un service cloud).
