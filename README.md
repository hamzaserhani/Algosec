# AlgoSec FireFlow — Automatisation des tickets

Outils Python pour créer en masse des tickets *Traffic Change Request* dans
AlgoSec FireFlow à partir d'un fichier de demandes (Excel/CSV), avec nettoyage
des données et vérification post-création.

## 📖 Documentation

➡️ **[PROCEDURE.md](PROCEDURE.md)** — le guide complet, étape par étape
(réutilisable pour chaque nouveau lot ou template).

## 🚀 Démarrage rapide

```bash
# 1. Config (une fois) : copier et remplir
cp config.example.json config.json

# 2. Nettoyer le fichier de demandes
python scripts/clean_requests.py demandes.csv -o demandes_clean.csv

# 3. Aperçu sans envoyer
python scripts/bulk_create_requests.py demandes_clean.csv --dry-run

# 4. Créer les tickets
python scripts/bulk_create_requests.py demandes_clean.csv

# 5. Vérifier (ticket créé == demande)
python scripts/verify_tickets.py demandes_clean.csv
```

## 🧰 Scripts

| Script | Rôle |
|--------|------|
| `scripts/inspect_ticket_fields.py` | Découvre les noms exacts des champs d'un template |
| `scripts/clean_requests.py` | Nettoie le fichier de demandes (non destructif) |
| `scripts/bulk_create_requests.py` | Crée les tickets en masse |
| `scripts/verify_tickets.py` | Post-check : compare chaque ticket à la demande |
| `scripts/get_ticket.py` | Récupère les détails d'un ticket |
| `reporting/list_tickets.py`, `reporting/sla_report.py` | Reporting / SLA |

## ⚙️ Prérequis

- Python 3 + `requests` (`pip install requests`)
- Un `config.json` à la racine (voir `config.example.json`) — **non versionné**
  (contient les identifiants).

## 📌 Points clés

- **`#` unique** par demande (clé de l'historique idempotent).
- L'historique (`request_history/`) évite de recréer un ticket déjà fait.
- `verify_tickets.py` est la **source de vérité** : il relit le ticket réel.
- Voir le tableau des erreurs API et leurs solutions dans
  [PROCEDURE.md](PROCEDURE.md#8-cas-particuliers-rencontrés-référence).
