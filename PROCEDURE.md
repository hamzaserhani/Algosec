# Procédure — Création en masse de tickets AlgoSec FireFlow

Guide de bout en bout pour transformer un fichier de demandes (Excel/CSV) en
tickets *Traffic Change Request* dans FireFlow, avec vérification.

Réutilisable pour un **nouveau lot** ou un **nouveau template** : la logique ne
change pas, seule la config (template + champs) évolue.

---

## 1. Vue d'ensemble

```
demandes.csv/.xlsx
      │
      ▼  clean_requests.py        (nettoyage non destructif -> demandes_clean.csv)
      │
      ▼  bulk_create_requests.py  (création des tickets + colonne ALGOSEC + historique)
      │
      ▼  verify_tickets.py        (post-check : ticket créé == demande ?)
```

Outils :

| Script | Rôle |
|--------|------|
| `scripts/inspect_ticket_fields.py` | Découvre les **noms exacts** des champs d'un template (à partir d'un ticket existant) |
| `scripts/clean_requests.py` | Nettoie le fichier de demandes **sans perdre de données** |
| `scripts/bulk_create_requests.py` | Crée les tickets en masse |
| `scripts/verify_tickets.py` | Vérifie que chaque ticket correspond à la demande (read-after-write) |

---

## 2. Prérequis

- **Python 3** avec `requests` installé (`pip install requests`).
- Un fichier **`config.json`** à la racine (voir `config.example.json`). Il n'est
  **pas** versionné (contient les identifiants). Chaque machine a le sien.
- Accès réseau à l'AlgoSec cible (`server` dans la config).

### Structure de `config.json`

```json
{
    "server": "https://aspm.dir.ucb-group.com",
    "api_path": "/aff/api/external",
    "username": "...",
    "password": "...",
    "domain": "0",
    "verify_ssl": false,
    "template": "NPS - Firewall Rule Request - Add Firewall Rule",
    "user": "Any",
    "fields": {
        "NPS - ... - MSI code": "SX41",
        "NPS - ... - Design val number": "val-0150078",
        "NPS - ... - Permanent": "Yes",
        "NPS - ... - Source Zone": "Inside",
        "NPS - ... - Destination Zone": "Inside",
        "NPS - ... - UCB System Integrity": "High",
        "NPS - ... - UCB System Confidentiality": "High",
        "NPS - ... - UCB System Maintained and Secured": "Yes"
    },
    "traffic_fields": {
        "NPS - ... - Justification per traffic line": "{purpose}"
    },
    "source_object_map": {
        "SX41-GBL-USR-APP": {
            "sources": ["GLOBAL-UCB-USERS"],
            "user": "SX41-GBL-USR-APP"
        }
    }
}
```

- **`fields`** : champs obligatoires du template, envoyés avec la clé `key`.
- **`traffic_fields`** : champs au **niveau ligne de trafic**, envoyés avec `name`.
  Placeholders disponibles : `{purpose}`, `{subject}`, `{description}`.
- **`source_object_map`** : remplace une source nommée (objet non-IP) par des
  subnets/objets et place la valeur dans le champ **User** de la ligne.

---

## 3. Nouveau template → découvrir les champs (une fois par template)

Chaque template a ses propres champs obligatoires, avec des **noms internes
précis**. Pour les connaître, on inspecte un **ticket existant** de ce template.

```bash
python scripts/inspect_ticket_fields.py <ID_ticket_existant> --json ref.json
```

La sortie donne :
- le **type de formulaire** (Traffic / Generic / Object / Rule Removal),
- la liste **« Champs détectés »** avec les noms exacts,
- un **squelette `fields`** prêt à coller dans `config.json`.

> Copier les champs préfixés (`NPS - ... - ...`) dans `config.json`. Ignorer les
> champs calculés/lecture-seule (Risk Level, approveEngineer, status, etc.).

---

## 4. Format du fichier de demandes

Colonnes attendues (l'ordre importe peu, matching sur le nom d'en-tête) :

```
#, Purpose, Status, source, application, Target, By when,
Source IP, Target IP, TCP-IP range, F/W Application, [User]
```

- **`#`** : identifiant **unique** de la demande (clé de l'historique).
- **`Source IP` / `Target IP`** : requis (sinon la ligne est ignorée). Valeurs
  multiples via `|`, `,`, `;`, retour ligne, ou espace.
- **`TCP-IP range`** : ports (numériques ou plages). `F/W Application` = protocole.

Le cleaner gère automatiquement : plages `A to B` → `A-B`, `host (1.2.3.4)` →
`1.2.3.4`, wildcards `*.sap.com` → `sap.com`, encodage Excel (cp1252),
demandes réparties sur plusieurs lignes.

---

## 5. Étapes d'exécution

### 5.1 Nettoyer

```bash
python scripts/clean_requests.py demandes.csv -o demandes_clean.csv
```

- Le fichier d'origine n'est **jamais** modifié.
- Lire le **RAPPORT** en bas : doublons de `#`, valeurs sans IP (hostnames/URLs
  à vérifier), ports non numériques. Corriger `demandes.csv` si besoin et relancer.

### 5.2 Dry-run (aperçu, rien envoyé)

```bash
python scripts/bulk_create_requests.py demandes_clean.csv --dry-run
```

Vérifier la dernière ligne : `X A CREER, Y déjà existante(s), Z en alerte`.
- `Z en alerte` doit être **0** (sinon un ticket existe avec un contenu différent).
- Pas d'alerte **doublon `#`** en haut.

### 5.3 Créer

```bash
python scripts/bulk_create_requests.py demandes_clean.csv
```

- Les demandes déjà créées (historique) sont **sautées** (idempotent).
- Une demande en échec **n'interrompt pas** le lot ; récap des échecs à la fin.
- La colonne **`ALGOSEC`** du fichier est remplie avec l'ID de chaque ticket.

### 5.4 Vérifier (post-check)

```bash
python scripts/verify_tickets.py demandes_clean.csv
```

Compare, pour chaque ticket, les **sources/destinations/services réels** (GET)
avec la demande. Objectif : **0 mismatch**.
- `MANQUANT` = demandé mais absent du ticket.
- `EN TROP` = présent dans le ticket mais pas demandé.

---

## 6. Options utiles

| Option | Effet |
|--------|-------|
| `--only 244,246,270` | Ne traiter que ces `#` (ciblage déterministe) |
| `--force` | Recréer même si présent dans l'historique |
| `--split-destinations` | Une ligne de trafic **par destination** (évite le mix FQDN/IP) |
| `--history-dir <dir>` | Dossier d'historique dédié (ex. séparer Dev/Prod) |
| `--template "..."` | Forcer un template (surcharge la config) |
| `--config <fichier>` | Utiliser un autre `config.json` (ex. `config.prod.json`) |
| `--no-track` | Ne pas écrire la colonne ALGOSEC |
| `--delay <s>` | Délai entre requêtes (défaut 1s) |

---

## 7. Corriger une demande erronée

1. Identifier le(s) `#` en `MISMATCH` via `verify_tickets.py`.
2. Corriger la donnée dans `demandes.csv`, régénérer `demandes_clean.csv`.
3. **Annuler** l'ancien ticket dans FireFlow (pas d'API d'annulation — manuel).
4. Retirer son entrée d'historique : `request_history/<#>.json`.
5. Recréer : `bulk_create_requests.py demandes_clean.csv --only <#>`.
6. Re-vérifier.

> `--force` recrée sans supprimer l'historique, mais pense à annuler l'ancien
> ticket côté FireFlow pour éviter les doublons.

---

## 8. Cas particuliers rencontrés (référence)

| Erreur API | Cause | Solution |
|------------|-------|----------|
| `TEMPLATE_IS_DISABLED` | Template désactivé | Utiliser un template activé (`template` config) |
| `FIELD_NOT_IN_TEMPLATE` / `FIELD_NOT_FOUND` | Nom de champ inexact | Inspecter un ticket, utiliser le **nom complet** ; champs ticket avec clé `key` |
| `MANDATORY_FIELD_MISSING` | Champ obligatoire absent | L'ajouter dans `fields` |
| `BAD_COOKIE_HEADER` | Mauvais endpoint de lecture | Lecture = `change-requests/traffic|generic/{id}` |
| `APPLICATION_DEFAULT_*` | `application-default` non supporté ici | Mappé vers `any` / ports numériques |
| `INVALID_VALUE ... source` | Objet source inconnu | Vraie IP, ou `source_object_map` |
| `INVALID_MIX_OF_SPECIAL_AND_OTHER...` | Mix FQDN/IP dans une ligne | `--split-destinations` |
| `EXTERNAL_VALIDATION_FAILED ... use X instead` | Objet interdit | Utiliser l'objet indiqué (ex. `GLOBAL-UCB-USERS`) |

---

## 9. Notes importantes

- **`#` unique** : deux lignes avec le même `#` → une seule créée, l'autre sautée.
  Le dry-run **alerte** sur les doublons.
- **Historique** (`request_history/`) : indexé par `#`. Il rend les runs
  idempotents mais reflète l'état **à la création** — la source de vérité reste
  `verify_tickets.py` (qui relit le ticket réel).
- **Séparer les environnements** : utiliser `--history-dir request_history_prod`
  pour ne pas mélanger Dev et Prod.
- **Aucune API d'annulation/suppression** de ticket : les corrections passent par
  l'annulation manuelle côté FireFlow + recréation.
