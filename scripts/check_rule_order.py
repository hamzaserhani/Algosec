"""
Pourquoi ma regle d'autorisation ne prend pas effet ? (ordre / shadowing)

Donne un flux (src/dst/port) + le NOM de ta regle d'autorisation. Le script :
    1. Charge la rulebase EFFECTIVE du firewall (shared + device-group, dans l'ordre
       d'evaluation reel : shared pre -> DG pre -> local -> DG post -> shared post).
    2. Localise ta regle (presente ? a quelle position ? shared ou DG ?).
    3. Liste les regles AVANT elle qui pourraient matcher ce flux (source + service)
       -> surtout les DENY/block qui la SHADOW (evaluees en premier = elles gagnent).
    4. Conclut : regle absente (push/DG ?), shadow par un block, ou OK (chercher
       ailleurs : zones, categorie URL/SNI, logs anciens).

Lecture seule. Usage:
    python check_rule_order.py --src 10.120.0.0/22 --dst 48.209.133.15 --port 443 --proto tcp \
        --rule RISE-Login_Microsoft_outbound_HTTPS_connectivity --serial pazcweufwp01
"""

import argparse

from panorama_client import PanoramaClient
from policy_engine import PolicyEngine


def resolve_serial(pano, value):
    try:
        devices = pano.list_devices()
    except Exception:
        return value
    if value in {d["serial"] for d in devices}:
        return value
    m = [d for d in devices if d.get("hostname", "").lower() == value.lower()]
    if m:
        print(f"[INFO] hostname '{value}' -> serial {m[0]['serial']}")
        return m[0]["serial"]
    return value


def svc_cover(engine, services, proto, port):
    for s in services:
        r = engine.resolve_svc(s)
        if r == "any":
            return True
        if r == "app-default":
            return True  # couvre potentiellement (port = defaut de l'app)
        for (p, lo, hi) in r:
            if p == proto and lo <= port <= hi:
                return True
    return False


def main():
    p = argparse.ArgumentParser(description="Diagnostic d'ordre/shadowing d'une regle (lecture seule)")
    p.add_argument("--src", required=True)
    p.add_argument("--dst", required=True, help="IP destination (pour tester le match source+dest)")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--proto", default="tcp")
    p.add_argument("--rule", required=True, help="Nom EXACT de ta regle d'autorisation")
    p.add_argument("--serial", required=True, help="Serial ou hostname du firewall")
    p.add_argument("--config")
    p.add_argument("--dev", action="store_true")
    args = p.parse_args()

    config_path = args.config or ("config-dev.json" if args.dev else "config.json")
    print(f"[INFO] config: {config_path}")
    pano = PanoramaClient(config_path)
    pano.keygen()
    serial = resolve_serial(pano, args.serial)

    eng = PolicyEngine(pano, serial)
    n = eng.load_firewall_rules()
    eng.load_objects()
    print(f"[OK] {n} regles effectives (ordre d'evaluation).\n")

    src_ip = args.src.split("/")[0]

    # 1. Localiser la regle
    idx = next((i for i, r in enumerate(eng.rules) if r["name"] == args.rule), None)
    print("=" * 64)
    if idx is None:
        print(f"[ABSENTE] La regle '{args.rule}' n'est PAS dans la rulebase effective de ce firewall.")
        print("   Causes probables :")
        print("   - le push/commit n'a pas atteint cette instance (Cloud NGFW) ou ce device-group,")
        print("   - la regle est dans un AUTRE device-group non applique a ce firewall,")
        print("   - nom different (verifier l'orthographe exacte).")
        print("   Regles dont le nom ressemble :")
        for r in eng.rules:
            if args.rule.lower()[:12] in r["name"].lower():
                print(f"     - '{r['name']}' (loc={r['loc']}, action={r['action']})")
        print("=" * 64)
        return

    rule = eng.rules[idx]
    print(f"[TROUVEE] '{args.rule}' : position {idx+1}/{n}, section={rule['section']}, loc={rule['loc']}")
    print(f"          action={rule['action']} from={rule['from']} to={rule['to']}")
    print(f"          source={rule['source'][:4]} dest={rule['destination'][:4]}")
    print(f"          service={rule['service']} app={rule['application']} category={rule['category']}")

    # 2. La regle matche-t-elle le flux (source + dest + service) ?
    try:
        s_ok = eng._addr_match(rule["source"], src_ip)
        d_ok = eng._addr_match(rule["destination"], args.dst)
    except Exception:
        s_ok = d_ok = False
    v_ok = svc_cover(eng, rule["service"], args.proto, args.port)
    print(f"\n   Match du flux par CETTE regle : source={s_ok} dest={d_ok} service={v_ok}")
    if not (s_ok and d_ok and v_ok):
        print("   [!] La regle elle-meme ne matche pas le flux sur source/dest/service :")
        if not s_ok:
            print("       - SOURCE : l'objet source de la regle ne contient pas " + src_ip)
        if not d_ok:
            print(f"       - DESTINATION : l'objet dest ne contient pas {args.dst} "
                  "(si la regle est basee URL-categorie, c'est normal : dest=any + SNI dans la categorie).")
        if not v_ok:
            print("       - SERVICE : ne couvre pas " + f"{args.proto}/{args.port}")

    # 3. Shadowing : regles AVANT elle qui matchent source+service (surtout deny/block)
    print(f"\n   Regles AVANT '{args.rule}' pouvant la SHADOW (source+service compatibles) :")
    shadow_found = False
    for i in range(idx):
        r = eng.rules[i]
        if r["disabled"]:
            continue
        try:
            rs = eng._addr_match(r["source"], src_ip)
        except Exception:
            rs = False
        rv = svc_cover(eng, r["service"], args.proto, args.port)
        # dest : match direct OU dest=any OU regle URL-cat (dest souvent any)
        try:
            rd = eng._addr_match(r["destination"], args.dst)
        except Exception:
            rd = False
        dest_maybe = rd or r["destination"] == ["any"]
        if rs and rv and dest_maybe:
            url_gated = bool(r["category"]) and r["category"] != ["any"]
            if r["action"] == "allow":
                tag = "  (allow - prend le flux avant si applicable)"
            elif url_gated:
                # deny conditionne a une categorie URL -> ne shadow QUE si le domaine
                # du flux est dans cette categorie (pas un shadow systematique)
                tag = f"  (deny CONDITIONNEL a la categorie {r['category']} - shadow seulement si le domaine y est)"
            else:
                tag = "  <== BLOCK/DENY inconditionnel (SHADOW PROBABLE)"
                shadow_found = True
            print(f"     #{i+1} '{r['name']}' action={r['action']} loc={r['loc']} "
                  f"cat={r['category']}{tag}")

    # 4. Conclusion
    print("\n>>> CONCLUSION :")
    if not (s_ok and d_ok and v_ok):
        print("    La regle NE MATCHE PAS ce flux telle quelle (voir [!] ci-dessus).")
        print("    - si URL-categorie : verifier que le DOMAINE/SNI reel est dans la categorie,")
        print("    - verifier aussi les ZONES from/to (doivent correspondre au chemin du flux).")
    elif shadow_found:
        print("    Une regle situee AVANT matche aussi ce flux -> si c'est un BLOCK, il")
        print("    s'applique en premier et ta regle ne sert jamais. Deplacer ta regle AU-DESSUS")
        print("    du block, ou affiner le block.")
    else:
        print("    La regle matche et rien ne la shadow -> si le flux echoue encore :")
        print("    1) LOGS ANCIENS : re-tester sur une fenetre APRES le push (diagnose_flow --days 1),")
        print("    2) ZONES from/to de la regle vs chemin reel,")
        print("    3) categorie URL / SNI reel du trafic (pas exactement le domaine attendu),")
        print("    4) push pas encore synchronise sur toutes les instances Cloud NGFW.")
    print("=" * 64)


if __name__ == "__main__":
    main()
