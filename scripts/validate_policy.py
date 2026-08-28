"""
Fiabilise le moteur de policy en le validant contre les LOGS (verite terrain).

Tire un echantillon de sessions ALLOWED recentes dans Panorama, puis demande au
moteur de policy son verdict pour chacune. Comme les logs montrent la session
REELLEMENT autorisee (et la regle exacte), tout ecart = bug du moteur a corriger.

Mesure :
    - concordance : le moteur dit ALLOWED sur un flux que le firewall a autorise
    - regle : le moteur matche-t-il la MEME regle que le log ?
    - ecarts : flux autorises que le moteur ne trouve pas ALLOWED (a diagnostiquer)

Usage:
    python validate_policy.py --days 7 --nlogs 200
    python validate_policy.py --days 7 --nlogs 200 --json validation.json
"""

import argparse
import datetime
import json

from panorama_client import PanoramaClient
from policy_engine import PolicyEngine


def build_allow_query(since_str, extra=None):
    q = f"(action eq allow) and (time_generated geq '{since_str}')"
    if extra:
        q += f" and ({extra})"
    return q


def parse_proto(entry):
    p = (entry.get("proto") or "").lower()
    if p in ("tcp", "6"):
        return "tcp"
    if p in ("udp", "17"):
        return "udp"
    return None


def main():
    parser = argparse.ArgumentParser(description="Valide le moteur policy contre les logs")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--days", type=int, default=2, help="Fenetre logs (jours)")
    parser.add_argument("--nlogs", type=int, default=50, help="Taille de l'echantillon")
    parser.add_argument("--timeout", type=int, default=240, help="Timeout requete log (s)")
    parser.add_argument("--filter", dest="extra_filter",
                        help="Filtre log additionnel pour accelerer/cibler (ex: \"addr.src in 10.120.0.0/16\")")
    parser.add_argument("--json", dest="json_path", help="Rapport detaille JSON")
    parser.add_argument("--use-app", action="store_true", help="Passer l'App-ID du log au moteur (mode app-aware)")

    args = parser.parse_args()

    with open(args.config, "r") as f:
        cfg = json.load(f)
    # name<->serial des firewalls configures
    fw_by_serial = {fw["serial"]: fw["name"] for fw in (cfg.get("policy_firewalls") or [])}
    fw_by_name = {fw["name"].lower(): fw["serial"] for fw in (cfg.get("policy_firewalls") or [])}
    if not fw_by_serial:
        print("[ERREUR] Aucun 'policy_firewalls' dans config.json.")
        return

    pano = PanoramaClient(args.config)
    pano.keygen()

    since = datetime.datetime.now() - datetime.timedelta(days=args.days)
    since_str = since.strftime("%Y/%m/%d %H:%M:%S")
    print(f"[...] Echantillon de {args.nlogs} sessions ALLOWED depuis {since_str}"
          + (f" (filtre: {args.extra_filter})" if args.extra_filter else "") + "...")
    logs = pano.query_traffic_log(build_allow_query(since_str, args.extra_filter),
                                  nlogs=args.nlogs, max_wait=args.timeout)
    print(f"[OK] {len(logs)} sessions recuperees.")

    engines = {}  # serial -> PolicyEngine (charge a la demande)

    def get_engine(serial):
        if serial not in engines:
            print(f"[...] Chargement policy {fw_by_serial.get(serial, serial)} ({serial})...")
            eng = PolicyEngine(pano, serial)
            eng.load_firewall_rules()
            eng.load_objects()
            engines[serial] = eng
        return engines[serial]

    stats = {"total": 0, "ok_allowed": 0, "same_rule": 0, "not_allowed": 0,
             "skipped_no_fw": 0, "skipped_no_proto": 0}
    discrepancies = []

    for e in logs:
        proto = parse_proto(e)
        if not proto or not e.get("dport") or not e.get("src") or not e.get("dst"):
            stats["skipped_no_proto"] += 1
            continue
        # Trouve le firewall qui a logge (serial ou device_name -> serial configure)
        serial = e.get("serial")
        if serial not in fw_by_serial:
            dn = (e.get("device_name") or "").lower()
            serial = fw_by_name.get(dn)
        if not serial:
            stats["skipped_no_fw"] += 1
            continue

        stats["total"] += 1
        eng = get_engine(serial)
        app = e.get("app") if args.use_app else None
        try:
            res = eng.evaluate(e["src"], e["dst"], proto, int(e["dport"]), flow_app=app)
        except Exception as ex:
            res = {"status": "ERROR", "rule": str(ex).splitlines()[0]}

        if res["status"] == "ALLOWED":
            stats["ok_allowed"] += 1
            if res.get("rule") and e.get("rule") and res["rule"] == e["rule"]:
                stats["same_rule"] += 1
        else:
            stats["not_allowed"] += 1
            discrepancies.append({
                "src": e["src"], "dst": e["dst"], "svc": f"{proto}/{e['dport']}",
                "app": e.get("app"), "log_rule": e.get("rule"),
                "engine_status": res["status"], "engine_rule": res.get("rule"),
                "note": res.get("note"), "firewall": fw_by_serial.get(serial, serial),
            })

    print(f"\n{'='*50}")
    print(f"Sessions evaluees        : {stats['total']}")
    print(f"  moteur = ALLOWED       : {stats['ok_allowed']}"
          + (f"  (dont meme regle: {stats['same_rule']})" if stats['ok_allowed'] else ""))
    print(f"  moteur != ALLOWED      : {stats['not_allowed']}  <-- ecarts a diagnostiquer")
    print(f"Ignorees (pas de FW/proto): {stats['skipped_no_fw']}+{stats['skipped_no_proto']}")
    if stats["total"]:
        taux = 100.0 * stats["ok_allowed"] / stats["total"]
        print(f"\n>>> Concordance moteur/logs : {taux:.1f}%")

    if discrepancies:
        print(f"\n--- Ecarts ({len(discrepancies)}, max 15 affiches) ---")
        for d in discrepancies[:15]:
            print(f"  {d['src']}->{d['dst']} {d['svc']} app={d['app']} "
                  f"| log_rule={d['log_rule']} | moteur={d['engine_status']} ({d['engine_rule']})")

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump({"stats": stats, "discrepancies": discrepancies}, f, indent=2, ensure_ascii=False)
        print(f"\n[OK] Rapport -> {args.json_path}")


if __name__ == "__main__":
    main()
