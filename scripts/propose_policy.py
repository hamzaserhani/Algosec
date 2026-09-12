"""
Propose une POLICY pour un flux qui tombe sur le deny par defaut (interzone-default),
en s'appuyant sur les regles d'autorisation DEJA implementees (conventions existantes).

PROPOSITION UNIQUEMENT : ce script ne modifie RIEN sur le firewall. Il genere un
projet motive, a faire valider par l'equipe firewall/securite.

Logique :
    1. Charge la rulebase effective du firewall (reuse PolicyEngine).
    2. Confirme que le flux n'est couvert par aucune regle allow (il tomberait sur
       le deny par defaut).
    3. Trouve les regles allow "modeles" dont la SOURCE couvre deja ce flux et dont
       le SERVICE correspond (HTTPS/port) -> conventions a reutiliser.
    4. Propose :
       A. ETENDRE l'existant : ajouter la destination/domaine a la categorie URL
          custom (ou a l'address-group destination) de la regle modele.
       B. NOUVELLE regle : brouillon calque sur la regle modele la plus proche.

Usage:
    python propose_policy.py --src 10.120.0.0/22 --dst 48.209.133.15 --port 443 --proto tcp --serial pazcweufwp01
    python propose_policy.py --src 10.120.0.0/22 --url login.microsoft.com --port 443 --serial pazcweufwp01 --dev
"""

import argparse
import json

from panorama_client import PanoramaClient
from policy_engine import PolicyEngine


def resolve_serial(pano, value):
    """hostname -> serial vivant (Cloud NGFW autoscale), ou serial tel quel."""
    try:
        devices = pano.list_devices()
    except Exception:
        return value
    serials = {d["serial"] for d in devices}
    if value in serials:
        return value
    matches = [d for d in devices if d.get("hostname", "").lower() == value.lower()]
    if matches:
        print(f"[INFO] hostname '{value}' -> serial {matches[0]['serial']} "
              f"({len(matches)} instance(s) vivante(s))")
        return matches[0]["serial"]
    return value


def svc_covers_port(engine, services, proto, port):
    """La liste de services couvre-t-elle proto/port ? (ou application-default)."""
    for s in services:
        r = engine.resolve_svc(s)
        if r == "any":
            return "any"
        if r == "app-default":
            return "app-default"
        for (p, lo, hi) in r:
            if p == proto and lo <= port <= hi:
                return "port"
    return None


def score_template(rule, src_match, svc_cover, is_internet):
    """Score de pertinence d'une regle modele (plus haut = plus proche)."""
    s = 0
    if src_match:
        s += 3
    if svc_cover == "port":
        s += 3
    elif svc_cover in ("app-default", "any"):
        s += 2
    # regle orientee internet (categorie URL custom) si flux internet
    cat = rule["category"]
    url_based = bool(cat) and cat != ["any"]
    if is_internet and url_based:
        s += 3
    if not is_internet and not url_based:
        s += 1
    return s


def main():
    p = argparse.ArgumentParser(description="Propose une policy basee sur les regles existantes (PROPOSITION, pas de push)")
    p.add_argument("--src", required=True, help="Source du flux (IP/subnet)")
    p.add_argument("--dst", help="Destination IP (flux interne / IP connue)")
    p.add_argument("--url", help="Domaine (flux internet)")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--proto", default="tcp")
    p.add_argument("--serial", required=True, help="Serial ou hostname du firewall")
    p.add_argument("--config")
    p.add_argument("--dev", action="store_true")
    p.add_argument("--json", dest="json_path")
    args = p.parse_args()

    config_path = args.config or ("config-dev.json" if args.dev else "config.json")
    print(f"[INFO] config: {config_path}")

    pano = PanoramaClient(config_path)
    pano.keygen()
    serial = resolve_serial(pano, args.serial)

    eng = PolicyEngine(pano, serial)
    nr = eng.load_firewall_rules()
    eng.load_objects()
    print(f"[OK] {nr} regles effectives chargees.\n")

    dst = args.dst or ""
    is_internet = bool(args.url) or (dst and _is_public(dst))
    flow = f"{args.src} -> {args.dst or args.url} {args.proto}/{args.port}"

    # --- 1. Le flux est-il deja couvert par une regle allow ? ---
    covering = None
    if dst:
        res = eng.evaluate(args.src, dst, args.proto, args.port)
        if res["status"] == "ALLOWED":
            covering = res.get("rule")

    report = []
    R = report.append
    R(f"=== PROPOSITION DE POLICY pour : {flow} ===")
    R(f"(firewall {serial} - PROPOSITION, aucune modification appliquee)\n")

    if covering:
        R(f"[DEJA AUTORISE] Le flux est deja couvert par la regle '{covering}'.")
        R("   -> aucune nouvelle policy necessaire cote firewall (verifier appli/serveur).")
        _emit(report, args)
        return

    # --- 2. Trouver les regles modeles (source couvre + service correspond) ---
    candidates = []
    for rule in eng.rules:
        if rule["disabled"] or rule["action"] != "allow":
            continue
        try:
            src_match = eng._addr_match(rule["source"], args.src.split("/")[0])
        except Exception:
            src_match = False
        # source couvre si le subnet demande est inclus (test sur l'IP reseau)
        svc_cover = svc_covers_port(eng, rule["service"], args.proto, args.port)
        if not (src_match or svc_cover):
            continue
        sc = score_template(rule, src_match, svc_cover, is_internet)
        if sc >= 3:
            candidates.append((sc, rule, src_match, svc_cover))
    candidates.sort(key=lambda c: -c[0])

    R(f"[ANALYSE] {len(candidates)} regle(s) d'autorisation similaire(s) trouvee(s) "
      "(source et/ou service proches) :")
    for sc, rule, src_match, svc_cover in candidates[:6]:
        cat = rule["category"]
        url_based = bool(cat) and cat != ["any"]
        R(f"   - '{rule['name']}' [score {sc}] src_ok={bool(src_match)} service={svc_cover} "
          f"{'URL-cat=' + str(cat) if url_based else 'dest=' + str(rule['destination'][:3])}")
    R("")

    if not candidates:
        R(">>> Aucune regle modele proche -> proposer une NOUVELLE regle (voir ci-dessous).")
        _propose_new_rule(report, args, None, is_internet)
        _emit(report, args)
        return

    _sc, best, best_srcm, _svc = candidates[0]
    best_cat = best["category"]
    best_url_based = bool(best_cat) and best_cat != ["any"]

    R(">>> PROPOSITION(S) :")
    R("")
    # Option A : etendre l'existant
    if best_url_based and is_internet and args.url:
        R(f"  [A - RECOMMANDE] ETENDRE la regle existante '{best['name']}'")
        R(f"     Cette regle autorise deja {args.src} en HTTPS sortant via la/les")
        R(f"     categorie(s) URL custom : {best_cat}.")
        R(f"     Le domaine '{args.url}' n'y est probablement PAS -> d'ou le deny par defaut.")
        R(f"     ACTION PROPOSEE : ajouter '{args.url}' (et ses sous-domaines *.{args.url})")
        R(f"     a la categorie URL custom {best_cat} utilisee par cette regle.")
        R("     => le plus propre : respecte tes conventions, 0 nouvelle regle, faible risque.")
    elif best_srcm and not best_url_based and dst:
        R(f"  [A - RECOMMANDE] ETENDRE la regle existante '{best['name']}'")
        R(f"     Elle autorise {args.src} vers {best['destination'][:5]} sur ce service.")
        R(f"     La destination {dst} n'y est pas -> l'ajouter a l'address-group destination")
        R(f"     de cette regle (ou creer l'objet et l'ajouter).")
    else:
        R(f"  [A] La regle la plus proche est '{best['name']}' mais l'extension directe")
        R("     n'est pas evidente (mecanisme different). Voir l'option B.")
    R("")
    # Option B : nouvelle regle calquee
    _propose_new_rule(report, args, best, is_internet)

    _emit(report, args)


def _is_public(ip):
    import ipaddress
    try:
        return not ipaddress.ip_address(str(ip)).is_private
    except ValueError:
        return False


def _propose_new_rule(report, args, template, is_internet):
    R = report.append
    R("  [B] BROUILLON de nouvelle regle (a valider)"
      + (f", calque sur '{template['name']}'" if template else "") + " :")
    name = f"ALLOW-{args.src.replace('/', '_')}-to-{(args.url or args.dst or 'dest').replace('.', '_')}"
    src_zone = "<zone-source (cf regle modele)>" if template else "<zone-source>"
    dst_zone = "<zone-dest (cf regle modele)>" if template else "<zone-dest>"
    R(f"        name        : {name[:63]}")
    R(f"        from/to     : {src_zone} -> {dst_zone}")
    R(f"        source      : {args.src}")
    if is_internet and args.url:
        R(f"        destination : any")
        R(f"        category    : <categorie URL custom incluant {args.url}>  (a creer/etendre)")
        R(f"        application : {template['application'] if template else ['ssl', 'web-browsing']}")
        R(f"        service     : application-default")
    else:
        R(f"        destination : {args.dst}  (ou address-group dedie)")
        R(f"        application : any")
        R(f"        service     : {args.proto}/{args.port}")
    R(f"        action      : allow")
    if template:
        R(f"        profils     : reprendre ceux de '{template['name']}' (log, security, decryption)")
    R("        NB: brouillon indicatif -> l'equipe firewall valide zones/profils/position.")


def _emit(report, args):
    print("=" * 64)
    for line in report:
        print(line)
    print("=" * 64)
    print("\n[RAPPEL] Proposition uniquement. Aucune modification appliquee au firewall.")
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump({"proposal": report}, f, indent=2, ensure_ascii=False)
        print(f"[OK] Proposition -> {args.json_path}")


if __name__ == "__main__":
    main()
