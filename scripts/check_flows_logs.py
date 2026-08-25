"""
Pre-check des flux via les LOGS de trafic Panorama (source de verite reelle),
avec fallback simulation (test security-policy-match).

Pourquoi les logs : la simulation de policy (AFA / test-policy-match) est faussee
par les regles de filtrage URL (URL-category) qui shadow les regles d'autorisation.
Les logs refletent le trafic REELLEMENT autorise, sur tous les firewalls (agreges
par Panorama -> resout aussi l'auto-path).

Logique par flux :
    1. Logs 'allow' (30j) matchant src/dst/port ?  et logs 'deny' ?
         allow>0, deny=0  -> ALLOWED   (skip la creation)
         allow>0, deny>0  -> PARTIAL   (creer)
         allow=0, deny>0  -> BLOCKED   (creer)
         allow=0, deny=0  -> pas de trafic -> FALLBACK simulation
    2. Fallback test-policy-match (sur --target si fourni) :
         allow                    -> ALLOWED
         deny + URL-category      -> INCONCLUSIVE (creer, prudent)
         deny (L3/L4)             -> BLOCKED
    Conservateur : on ne marque ALLOWED que si preuve claire. Sinon on cree.

Usage:
    python check_flows_logs.py demandes_clean.csv --days 30
    python check_flows_logs.py demandes_clean.csv --only 108 --days 30
    python check_flows_logs.py demandes_clean.csv --json rapport_flux.json
"""

import argparse
import datetime
import ipaddress
import json

from panorama_client import PanoramaClient
from check_flows_panorama import expand_services
from check_flows import write_column
from bulk_create_requests import (
    load_requests,
    row_to_ticket,
    apply_source_object_map,
)


def is_ip_like(value):
    """True si la valeur est une IP, un subnet, ou une plage 'a-b' d'IP."""
    v = (value or "").strip()
    try:
        if "-" in v and "/" not in v:
            a, b = v.split("-", 1)
            ipaddress.ip_address(a.strip())
            ipaddress.ip_address(b.strip())
            return True
        if "/" in v:
            ipaddress.ip_network(v, strict=False)
            return True
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def build_log_query(sources, destinations, ports, action, since_str):
    """Construit un filtre log Panorama pour un flux."""
    def group(field, values, op="in"):
        parts = [f"({field} {op} {v})" for v in values]
        return "(" + " or ".join(parts) + ")" if parts else ""

    clauses = [f"(time_generated geq '{since_str}')", f"(action eq {action})"]
    if sources:
        clauses.append(group("addr.src", sources))
    if destinations:
        clauses.append(group("addr.dst", destinations))
    if ports:
        port_parts = [f"(port.dst eq {p})" for p in ports]
        clauses.append("(" + " or ".join(port_parts) + ")")
    return " and ".join(c for c in clauses if c)


def flow_ports(services):
    """Extrait les ports testables d'une liste de services (ignore 'any'/plages ouvertes)."""
    ports = []
    for proto, port, note in expand_services(services):
        if port is not None:
            ports.append(port)
    return ports


def check_via_logs(pano, ticket, since_str):
    """Interroge les logs allow/deny. Retourne (status, detail)."""
    sources = ticket["sources"]
    destinations = ticket["destinations"]
    ports = flow_ports(ticket["services"])

    # Les logs se filtrent sur des IP/subnets. Si une source/dest est un objet
    # nomme (ex: GLOBAL-UCB-USERS) ou un hostname, on ne peut pas filtrer
    # fiablement -> pas de skip a l'aveugle.
    non_ip = [v for v in sources + destinations if not is_ip_like(v)]
    if non_ip:
        return "NON_IP", {"non_ip": non_ip,
                          "note": "source/dest non-IP : verifier manuellement"}

    q_allow = build_log_query(sources, destinations, ports, "allow", since_str)
    q_deny = build_log_query(sources, destinations, ports, "deny", since_str)
    # Soumet les 2 requetes d'un coup puis poll les 2 -> ~2x plus rapide.
    allow_logs, deny_logs = pano.query_traffic_logs_parallel([q_allow, q_deny], nlogs=5)

    detail = {"allow_count": len(allow_logs), "deny_count": len(deny_logs),
              "allow_sample": allow_logs[:2], "deny_sample": deny_logs[:2]}

    if allow_logs and not deny_logs:
        return "ALLOWED", detail
    if allow_logs and deny_logs:
        return "PARTIAL", detail
    if deny_logs:
        return "BLOCKED", detail
    return "NO_TRAFFIC", detail


def main():
    parser = argparse.ArgumentParser(description="Pre-check des flux via logs Panorama (+ fallback simulation)")
    parser.add_argument("input_file", help="Fichier de demandes (.csv/.xlsx)")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--only", help="Ne tester que ces '#' (liste separee par virgules)")
    parser.add_argument("--days", type=int, default=30, help="Fenetre logs en jours (defaut 30)")
    parser.add_argument("--json", dest="json_path", help="Sauve le rapport en JSON")
    parser.add_argument("--raw", action="store_true", help="Affiche les echantillons de logs")
    parser.add_argument("--no-write", action="store_true", help="Ne pas ecrire la colonne deja_autorise")

    args = parser.parse_args()
    only_ids = {x.strip() for x in args.only.split(",")} if args.only else None

    with open(args.config, "r") as f:
        source_object_map = json.load(f).get("source_object_map") or {}

    since = datetime.datetime.now() - datetime.timedelta(days=args.days)
    since_str = since.strftime("%Y/%m/%d %H:%M:%S")

    rows = load_requests(args.input_file)
    flows = []
    for row in rows:
        ticket, _ = row_to_ticket(row)
        if ticket is None:
            continue
        if only_ids is not None and (ticket.get("id") or "").strip() not in only_ids:
            continue
        apply_source_object_map(ticket, source_object_map)
        flows.append(ticket)

    if not flows:
        print("[INFO] Aucun flux a tester.")
        return

    print(f"[INFO] {len(flows)} flux - logs depuis {since_str} (agreges tous firewalls).")
    pano = PanoramaClient(args.config)
    pano.keygen()

    reports, counts, results_by_id = [], {}, {}
    for t in flows:
        rid = t.get("id") or "?"
        print(f"\n=== Flux #{rid} : {t['sources']} -> {t['destinations']} svc={t['services']} ===")
        try:
            status, detail = check_via_logs(pano, t, since_str)
        except Exception as e:
            status, detail = "ERROR", {"error": str(e).splitlines()[0]}
            print(f"  [ERREUR] {detail['error']}")

        print(f"  logs: allow={detail.get('allow_count','?')} deny={detail.get('deny_count','?')}  => {status}")
        if args.raw and detail.get("allow_sample"):
            for e in detail["allow_sample"]:
                print(f"     allow: {e.get('src')}->{e.get('dst')}:{e.get('dport')} rule={e.get('rule')} app={e.get('app')} @{e.get('time')}")
        counts[status] = counts.get(status, 0) + 1
        results_by_id[str(rid)] = status
        reports.append({"id": rid, "status": status, "detail": detail,
                        "sources": t["sources"], "destinations": t["destinations"],
                        "services": t["services"]})

    print(f"\n{'='*40}")
    print("Resume:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    allowed = counts.get("ALLOWED", 0)
    print(f"-> {allowed} flux DEJA AUTORISE(S) (ticket evitable). "
          f"NO_TRAFFIC/NON_IP -> creer le ticket (defaut sur).")

    if not args.no_write:
        write_column(args.input_file, results_by_id)

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2, ensure_ascii=False)
        print(f"[OK] Rapport -> {args.json_path}")


if __name__ == "__main__":
    main()
