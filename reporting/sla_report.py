"""
Rapport SLA et volumes des tickets FireFlow.

Apercu des volumes de demandes AlgoSec et du respect des SLA par phase
de workflow, pour les templates custom configures dans config.json.

Periode par defaut : 3 derniers mois.
Phases : decouvertes automatiquement depuis l'historique workflow des tickets.
SLA cibles : declares dans config.json sous reporting.sla_hours[template][phase].

Usage:
    python sla_report.py
    python sla_report.py --since 2026-01-01 --until 2026-04-30
    python sla_report.py --template "Mon Template Custom"
    python sla_report.py --discover                       # lister les phases trouvees
    python sla_report.py --csv rapport.csv --html rapport.html --json rapport.json
    python sla_report.py --sla "Plan=24,Implement=48"     # override CLI
"""

import argparse
import csv
import json
import statistics
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

# Permet d'importer algosec_client depuis ../scripts/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from algosec_client import AlgosecClient  # noqa: E402


# Variations de noms de champs selon les versions FireFlow
HISTORY_KEYS = ["history", "workflow", "phases", "steps", "stepHistory", "workflowHistory"]
PHASE_NAME_KEYS = ["step", "phase", "name", "stepName", "phaseName"]
ENTERED_KEYS = ["enteredAt", "startDate", "startedAt", "start", "entered", "enterDate"]
EXITED_KEYS = ["completedAt", "endDate", "exitedAt", "end", "completed", "exited", "exitDate"]
TEMPLATE_KEYS = ["template", "templateName", "workflowTemplate"]
CREATED_KEYS = ["createDate", "created", "createdDate", "creationDate"]


def first_value(obj, keys):
    """Retourne la premiere valeur trouvee parmi keys."""
    if not isinstance(obj, dict):
        return None
    for k in keys:
        if k in obj and obj[k] is not None:
            return obj[k]
    return None


def parse_date(s):
    """Parse une date string en datetime, robuste a plusieurs formats."""
    if not s:
        return None
    if isinstance(s, datetime):
        return s
    s = str(s).rstrip("Z").split("+")[0]
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def extract_phases(ticket):
    """Extrait la liste de (phase_name, entered, exited) d'un ticket."""
    history = first_value(ticket, HISTORY_KEYS) or []
    if isinstance(history, dict):
        for k in ("steps", "phases", "history", "items"):
            if k in history and isinstance(history[k], list):
                history = history[k]
                break
        else:
            return []
    if not isinstance(history, list):
        return []

    phases = []
    for entry in history:
        if not isinstance(entry, dict):
            continue
        name = first_value(entry, PHASE_NAME_KEYS)
        entered = parse_date(first_value(entry, ENTERED_KEYS))
        exited = parse_date(first_value(entry, EXITED_KEYS))
        if name:
            phases.append((str(name), entered, exited))
    return phases


def fetch_tickets_list(client, since, until):
    """Recupere la liste des tickets dans la fenetre de dates."""
    print(f"\n[...] Liste des tickets ({since.date()} -> {until.date()})...")

    params = [
        ("createdFrom", since.strftime("%Y-%m-%d")),
        ("createdTo", until.strftime("%Y-%m-%d")),
    ]
    query = "&".join(f"{k}={v}" for k, v in params)
    result = client.get(f"change-requests?{query}")

    if result.get("status") != "Success":
        msgs = result.get("messages", [])
        err = msgs[0]["message"] if msgs else "Erreur inconnue"
        print(f"[ERREUR] Echec liste: {err}")
        return []

    data = result.get("data", {})
    tickets = data.get("changeRequests", data) if isinstance(data, dict) else data
    if not isinstance(tickets, list):
        tickets = [tickets]

    print(f"[OK] {len(tickets)} ticket(s) recupere(s).")
    return tickets


def fetch_ticket_details(client, ticket_id):
    """Recupere les details complets d'un ticket (avec historique workflow)."""
    try:
        result = client.get(f"change-requests/{ticket_id}")
        if result.get("status") == "Success":
            return result.get("data", {})
    except Exception as e:
        print(f"[WARN] Ticket {ticket_id}: {e}")
    return None


def fetch_all_details(client, tickets, workers=8):
    """Recupere en parallele les details de tous les tickets."""
    ids = [t.get("id") or t.get("changeRequestId") for t in tickets]
    ids = [i for i in ids if i is not None]
    if not ids:
        return []

    print(f"[...] Detail de {len(ids)} ticket(s) ({workers} workers)...")
    detailed = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(fetch_ticket_details, client, i): i for i in ids}
        for i, fut in enumerate(as_completed(futures), 1):
            res = fut.result()
            if res:
                detailed.append(res)
            if i % 25 == 0 or i == len(ids):
                print(f"  ... {i}/{len(ids)}")
    return detailed


def filter_by_template(tickets, templates):
    """Filtre les tickets par nom de template (set)."""
    if not templates:
        return tickets
    return [t for t in tickets if str(first_value(t, TEMPLATE_KEYS) or "") in templates]


def compute_volumes(tickets):
    """Calcule les metriques de volume."""
    vol = {"total": len(tickets), "par_statut": {}, "par_template": {}, "par_mois": {}}
    for t in tickets:
        status = str(t.get("status", "Inconnu"))
        vol["par_statut"][status] = vol["par_statut"].get(status, 0) + 1

        template = str(first_value(t, TEMPLATE_KEYS) or "Inconnu")
        vol["par_template"][template] = vol["par_template"].get(template, 0) + 1

        d = parse_date(first_value(t, CREATED_KEYS))
        if d:
            mois = d.strftime("%Y-%m")
            vol["par_mois"][mois] = vol["par_mois"].get(mois, 0) + 1
    return vol


def percentile(values, pct):
    """Percentile simple (sans interpolation)."""
    if not values:
        return 0
    s = sorted(values)
    idx = max(0, min(len(s) - 1, int(round(pct / 100 * len(s))) - 1))
    return s[idx]


def compute_sla(tickets, sla_config):
    """Calcule les metriques SLA par (template, phase)."""
    by_key = {}
    breaches = []

    for t in tickets:
        template = str(first_value(t, TEMPLATE_KEYS) or "Inconnu")
        ticket_id = t.get("id", t.get("changeRequestId", "?"))
        for name, entered, exited in extract_phases(t):
            if not entered or not exited:
                continue
            duration_h = (exited - entered).total_seconds() / 3600
            if duration_h < 0:
                continue
            by_key.setdefault((template, name), []).append(duration_h)

            sla_h = sla_config.get(template, {}).get(name)
            if sla_h is not None and duration_h > sla_h:
                breaches.append({
                    "ticket_id": ticket_id,
                    "template": template,
                    "phase": name,
                    "duration_h": round(duration_h, 2),
                    "sla_h": sla_h,
                    "depassement_h": round(duration_h - sla_h, 2),
                })

    summary = []
    for (template, phase), durs in by_key.items():
        sla_h = sla_config.get(template, {}).get(phase)
        within = sum(1 for d in durs if sla_h is None or d <= sla_h)
        summary.append({
            "template": template,
            "phase": phase,
            "count": len(durs),
            "avg_h": round(statistics.mean(durs), 2),
            "median_h": round(statistics.median(durs), 2),
            "p95_h": round(percentile(durs, 95), 2),
            "min_h": round(min(durs), 2),
            "max_h": round(max(durs), 2),
            "sla_h": sla_h,
            "within_sla_pct": round(100 * within / len(durs), 1) if sla_h is not None else None,
            "breaches": (len(durs) - within) if sla_h is not None else None,
        })
    summary.sort(key=lambda x: (x["template"], x["phase"]))
    breaches.sort(key=lambda x: -x["depassement_h"])
    return {"par_phase": summary, "depassements": breaches}


def print_volumes(vol):
    print(f"\n=== Volumes ===")
    print(f"Total: {vol['total']} ticket(s)\n")
    for label, key in [("Par statut", "par_statut"), ("Par template", "par_template")]:
        print(f"{label}:")
        for k, v in sorted(vol[key].items(), key=lambda x: -x[1]):
            print(f"  {k:<35} {v}")
        print()
    print("Par mois:")
    for k, v in sorted(vol["par_mois"].items()):
        print(f"  {k:<35} {v}")


def print_sla(sla):
    print(f"\n=== SLA par phase ===")
    rows = sla["par_phase"]
    if not rows:
        print("[INFO] Aucune donnee de phase disponible.")
        return
    fmt = "{:<25} {:<22} {:>6} {:>8} {:>8} {:>8} {:>8} {:>8} {:>10}"
    print(fmt.format("Template", "Phase", "Count", "Avg(h)", "Med(h)", "P95(h)", "SLA(h)", "%OK", "Breaches"))
    print("-" * 115)
    for r in rows:
        sla_s = str(r["sla_h"]) if r["sla_h"] is not None else "-"
        ok = f"{r['within_sla_pct']}%" if r["within_sla_pct"] is not None else "-"
        br = str(r["breaches"]) if r["breaches"] is not None else "-"
        print(fmt.format(
            r["template"][:25], r["phase"][:22],
            r["count"], r["avg_h"], r["median_h"], r["p95_h"], sla_s, ok, br,
        ))

    if sla["depassements"]:
        print(f"\n=== Depassements ({len(sla['depassements'])}) ===")
        for d in sla["depassements"][:20]:
            print(f"  Ticket {str(d['ticket_id']):<10} [{d['template']}/{d['phase']}] "
                  f"{d['duration_h']}h (SLA {d['sla_h']}h, +{d['depassement_h']}h)")
        if len(sla["depassements"]) > 20:
            print(f"  ... et {len(sla['depassements']) - 20} autre(s).")


def discover_phases(tickets):
    """Affiche les phases trouvees par template (utile pour pre-remplir config)."""
    by_template = {}
    for t in tickets:
        template = str(first_value(t, TEMPLATE_KEYS) or "Inconnu")
        for name, _, _ in extract_phases(t):
            by_template.setdefault(template, set()).add(name)

    print("\n=== Phases decouvertes ===")
    if not by_template:
        print("[WARN] Aucune phase trouvee. Verifie le format de l'historique workflow renvoye par l'API.")
        return
    suggestion = {}
    for template, phases in sorted(by_template.items()):
        print(f"\n{template}:")
        suggestion[template] = {}
        for p in sorted(phases):
            print(f"  - {p}")
            suggestion[template][p] = 24
    print(f"\n[INFO] Snippet a coller dans config.json sous \"reporting\":")
    print(json.dumps({"sla_hours": suggestion}, indent=2, ensure_ascii=False))


def export_csv(vol, sla, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["=== VOLUMES ==="])
        w.writerow(["Categorie", "Cle", "Valeur"])
        w.writerow(["Total", "", vol["total"]])
        for cat in ("par_statut", "par_template", "par_mois"):
            for k, v in sorted(vol[cat].items()):
                w.writerow([cat, k, v])

        w.writerow([])
        w.writerow(["=== SLA PAR PHASE ==="])
        w.writerow(["Template", "Phase", "Count", "Avg(h)", "Median(h)", "P95(h)",
                    "Min(h)", "Max(h)", "SLA(h)", "%OK", "Breaches"])
        for r in sla["par_phase"]:
            w.writerow([r["template"], r["phase"], r["count"], r["avg_h"], r["median_h"],
                        r["p95_h"], r["min_h"], r["max_h"], r["sla_h"],
                        r["within_sla_pct"], r["breaches"]])

        if sla["depassements"]:
            w.writerow([])
            w.writerow(["=== DEPASSEMENTS ==="])
            w.writerow(["Ticket", "Template", "Phase", "Duree(h)", "SLA(h)", "Depassement(h)"])
            for d in sla["depassements"]:
                w.writerow([d["ticket_id"], d["template"], d["phase"],
                            d["duration_h"], d["sla_h"], d["depassement_h"]])
    print(f"[OK] Export CSV: {path}")


def export_json(vol, sla, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"volumes": vol, "sla": sla}, f, indent=2, ensure_ascii=False, default=str)
    print(f"[OK] Export JSON: {path}")


def export_html(vol, sla, path, since, until):
    def kv_table(d, title):
        if not d:
            return f"<h3>{title}</h3><p>-</p>"
        rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in sorted(d.items()))
        return f"<h3>{title}</h3><table><tr><th>Cle</th><th>Valeur</th></tr>{rows}</table>"

    def sla_table(rows):
        if not rows:
            return "<p>Aucune donnee.</p>"
        head = "<tr>" + "".join(f"<th>{c}</th>" for c in
            ["Template", "Phase", "Count", "Avg(h)", "Med(h)", "P95(h)", "SLA(h)", "%OK", "Breaches"]) + "</tr>"
        body = ""
        for r in rows:
            sla_s = r["sla_h"] if r["sla_h"] is not None else "-"
            ok = f"{r['within_sla_pct']}%" if r["within_sla_pct"] is not None else "-"
            br = r["breaches"] if r["breaches"] is not None else "-"
            color = ""
            if r["within_sla_pct"] is not None:
                if r["within_sla_pct"] >= 95:
                    color = "background:#d4edda;"
                elif r["within_sla_pct"] >= 80:
                    color = "background:#fff3cd;"
                else:
                    color = "background:#f8d7da;"
            body += (f'<tr style="{color}"><td>{r["template"]}</td><td>{r["phase"]}</td>'
                     f'<td>{r["count"]}</td><td>{r["avg_h"]}</td><td>{r["median_h"]}</td>'
                     f'<td>{r["p95_h"]}</td><td>{sla_s}</td><td>{ok}</td><td>{br}</td></tr>')
        return f"<table>{head}{body}</table>"

    def breach_table(rows):
        if not rows:
            return "<p>Aucun depassement.</p>"
        head = "<tr><th>Ticket</th><th>Template</th><th>Phase</th><th>Duree(h)</th><th>SLA(h)</th><th>Depassement(h)</th></tr>"
        body = "".join(f"<tr><td>{r['ticket_id']}</td><td>{r['template']}</td><td>{r['phase']}</td>"
                       f"<td>{r['duration_h']}</td><td>{r['sla_h']}</td><td>{r['depassement_h']}</td></tr>"
                       for r in rows)
        return f"<table>{head}{body}</table>"

    html = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><title>Rapport AlgoSec FireFlow</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 1100px; margin: 2em auto; color: #222; padding: 0 1em; }}
h1, h2, h3 {{ color: #1a4480; }}
table {{ border-collapse: collapse; margin: 1em 0; width: 100%; font-size: 14px; }}
th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; }}
th {{ background: #f0f4f8; }}
.summary {{ background: #f8f9fa; padding: 1em; border-radius: 6px; border-left: 4px solid #1a4480; }}
.legend {{ font-size: 13px; color: #666; }}
</style></head><body>
<h1>Rapport AlgoSec FireFlow</h1>
<div class="summary">
  <strong>Periode :</strong> {since.date()} - {until.date()}<br>
  <strong>Total tickets :</strong> {vol['total']}<br>
  <strong>Genere le :</strong> {datetime.now().strftime("%Y-%m-%d %H:%M")}
</div>
<h2>Volumes</h2>
{kv_table(vol['par_statut'], 'Par statut')}
{kv_table(vol['par_template'], 'Par template')}
{kv_table(vol['par_mois'], 'Par mois')}
<h2>SLA par phase</h2>
<p class="legend">Vert : %OK &ge; 95 &middot; Jaune : 80-94 &middot; Rouge : &lt; 80</p>
{sla_table(sla['par_phase'])}
<h2>Depassements de SLA</h2>
{breach_table(sla['depassements'])}
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[OK] Export HTML: {path}")


def parse_sla_override(s):
    """Parse 'Plan=24,Implement=48' en dict."""
    if not s:
        return {}
    out = {}
    for pair in s.split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            try:
                out[k.strip()] = float(v.strip())
            except ValueError:
                pass
    return out


def main():
    parser = argparse.ArgumentParser(description="Rapport SLA et volumes FireFlow")
    parser.add_argument("--config", default="config.json", help="Chemin vers config.json")
    parser.add_argument("--since", help="Date debut YYYY-MM-DD (defaut: -90j)")
    parser.add_argument("--until", help="Date fin YYYY-MM-DD (defaut: aujourd'hui)")
    parser.add_argument("--template", action="append", help="Filtrer par template (repetable)")
    parser.add_argument("--sla", help="Override SLA: 'Plan=24,Implement=48' (applique a tous les templates)")
    parser.add_argument("--discover", action="store_true", help="Lister les phases trouvees et quitter")
    parser.add_argument("--workers", type=int, default=8, help="Workers paralleles pour fetch detail (defaut: 8)")
    parser.add_argument("--csv", dest="csv_path", help="Export CSV")
    parser.add_argument("--json", dest="json_path", help="Export JSON")
    parser.add_argument("--html", dest="html_path", help="Export HTML")

    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    rep_cfg = cfg.get("reporting", {})
    templates = args.template or rep_cfg.get("templates")
    sla_config = {k: dict(v) for k, v in rep_cfg.get("sla_hours", {}).items()}

    cli_sla = parse_sla_override(args.sla)
    if cli_sla:
        target_keys = list(sla_config.keys()) or (templates or ["_default"])
        for tpl in target_keys:
            sla_config.setdefault(tpl, {}).update(cli_sla)

    until = datetime.strptime(args.until, "%Y-%m-%d") if args.until else datetime.now()
    since = datetime.strptime(args.since, "%Y-%m-%d") if args.since else (until - timedelta(days=90))

    client = AlgosecClient(args.config)
    client.authenticate()

    tickets = fetch_tickets_list(client, since, until)
    if templates:
        before = len(tickets)
        tickets = filter_by_template(tickets, set(templates))
        print(f"[INFO] Filtre template: {before} -> {len(tickets)} ticket(s).")

    if not tickets:
        print("[INFO] Aucun ticket sur la periode/template. Rien a faire.")
        return

    detailed = fetch_all_details(client, tickets, workers=args.workers)

    if args.discover:
        discover_phases(detailed)
        return

    vol = compute_volumes(detailed)
    sla = compute_sla(detailed, sla_config)

    print_volumes(vol)
    print_sla(sla)

    if args.csv_path:
        export_csv(vol, sla, args.csv_path)
    if args.json_path:
        export_json(vol, sla, args.json_path)
    if args.html_path:
        export_html(vol, sla, args.html_path, since, until)


if __name__ == "__main__":
    main()
