"""
Recupere/dumpe la policy Panorama pour calibrer le moteur d'evaluation.

Etapes :
    1. --devicegroups          : dump 'show devicegroups' (trouver le DG d'un firewall)
    2. --find <hostname>       : device-group contenant ce firewall
    3. --dump <DG>             : dump regles + objets d'un device-group (structure XML)

Usage:
    python get_policy.py config.json --devicegroups
    python get_policy.py config.json --find GDCFWBCKN001
    python get_policy.py config.json --dump <DeviceGroup> --json policy_dump.json
"""

import argparse
import json
import re

from panorama_client import PanoramaClient

DEV = "localhost.localdomain"


def dg_xpath(dg, tail):
    return (f"/config/devices/entry[@name='{DEV}']/device-group/"
            f"entry[@name='{dg}']/{tail}")


SECTIONS = {
    "shared_pre_rules": "/config/shared/pre-rulebase/security/rules",
    "shared_post_rules": "/config/shared/post-rulebase/security/rules",
    "shared_address": "/config/shared/address",
    "shared_address_group": "/config/shared/address-group",
    "shared_service": "/config/shared/service",
    "shared_service_group": "/config/shared/service-group",
}
DG_SECTIONS = {
    "dg_pre_rules": "pre-rulebase/security/rules",
    "dg_post_rules": "post-rulebase/security/rules",
    "dg_address": "address",
    "dg_address_group": "address-group",
    "dg_service": "service",
    "dg_service_group": "service-group",
}


def count_entries(xml):
    return len(re.findall(r"<entry\b", xml or ""))


def first_entry(xml):
    m = re.search(r"(<entry\b.*?</entry>)", xml or "", re.S)
    return m.group(1) if m else "(aucune)"


def main():
    parser = argparse.ArgumentParser(description="Dump policy Panorama (calibration)")
    parser.add_argument("config", nargs="?", default="config.json")
    parser.add_argument("--devicegroups", action="store_true")
    parser.add_argument("--find", help="hostname/serial du firewall")
    parser.add_argument("--dump", help="nom du device-group a dumper")
    parser.add_argument("--json", dest="json_path", help="sauve le dump complet")

    args = parser.parse_args()
    pano = PanoramaClient(args.config)
    pano.keygen()

    if args.devicegroups:
        xml = pano._op("<show><devicegroups></devicegroups></show>")
        print(xml[:4000])
        return

    if args.find:
        dg = pano.find_device_group(args.find)
        print(f"Device-group de {args.find} : {dg}")
        return

    if args.dump:
        dump = {}
        print(f"=== Device-group: {args.dump} ===\n")
        for label, xpath in SECTIONS.items():
            xml = pano.get_config(xpath)
            dump[label] = xml
            print(f"[{label}] {count_entries(xml)} entree(s)")
        for label, tail in DG_SECTIONS.items():
            xml = pano.get_config(dg_xpath(args.dump, tail))
            dump[label] = xml
            print(f"[{label}] {count_entries(xml)} entree(s)")

        print("\n--- Exemple de REGLE (dg_pre_rules) ---")
        print(first_entry(dump.get("dg_pre_rules"))[:1500])
        print("\n--- Exemple d'OBJET ADRESSE (dg_address) ---")
        print(first_entry(dump.get("dg_address"))[:600])
        print("\n--- Exemple de SERVICE (dg_service) ---")
        print(first_entry(dump.get("dg_service"))[:600])

        if args.json_path:
            with open(args.json_path, "w", encoding="utf-8") as f:
                json.dump(dump, f, indent=2, ensure_ascii=False)
            print(f"\n[OK] Dump complet -> {args.json_path}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
