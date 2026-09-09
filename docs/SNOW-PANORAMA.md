# Intégration ServiceNow → Panorama (PAN-OS XML API)

Documentation de référence pour récupérer depuis ServiceNow les **objets
adresses** et **groupes d'adresses** de Panorama, via l'API XML PAN-OS.

Basée sur le script validé `scripts/get_panorama_objects.py`.

---

## 0. Principes de base (À LIRE EN PREMIER)

| Point | Détail |
|-------|--------|
| **Protocole** | API XML PAN-OS (réponses en **XML**, pas JSON) |
| **Base URL** | `https://<panorama>/api/` — ⚠️ garder le **`/` final** avant `?` |
| **Méthode** | `GET` (les paramètres passent en query string ; pas de body) |
| **Auth** | par **clé API** (générée une fois), PAS de cookie de session |
| **Réseau** | Panorama est en IP interne → depuis ServiceNow cloud, passer par un **MID Server** |
| **SSL** | certificat interne → importer le certif dans le keystore, ou MID Server qui l'accepte |

### ⚠️ Les 2 pièges qui causent 99% des erreurs

1. **`400 Missing value for parameter "type"`**
   → les paramètres n'arrivent pas à Panorama. Mettre **tous les params dans
   l'URL** (`/api/?type=...&...`), ou utiliser un POST form-urlencoded.
   Encoder le mot de passe s'il contient des caractères spéciaux (`&`, `#`, `+`…).

2. **`403 Invalid Credential` alors que la clé semble bonne**
   → la **clé API est mal transmise**. Les clés PAN-OS contiennent `+`, `/`, `=`
   qui sont **corrompus en query string** (`+` devient espace).
   **Solution : passer la clé dans le header `X-PAN-KEY`** (aucun encodage requis),
   OU l'URL-encoder (`+`→`%2B`, `/`→`%2F`, `=`→`%3D`).
   Ne JAMAIS double-encoder (pas de `quote()` puis ré-encodage).

---

## 1. Générer la clé API (une fois, ou à rafraîchir)

| | |
|---|---|
| **Method** | `GET` |
| **Endpoint** | `https://<panorama>/api/` |
| **Query params** | `type=keygen` · `user=<user>` · `password=<password>` |
| **Headers** | *(aucun)* |
| **Body** | *(aucun)* |

**URL complète :**
```
https://gdcpamgmt002.dir.ucb-group.com/api/?type=keygen&user=apisnow&password=<MDP_ENCODE>
```

> Si le mot de passe a des caractères spéciaux : l'encoder, OU préférer un **POST**
> form-urlencoded :
> ```
> POST https://<panorama>/api/
> Content-Type: application/x-www-form-urlencoded
> Body: type=keygen&user=apisnow&password=<MDP>
> ```

**Réponse (XML) :**
```xml
<response status="success"><result><key>LUFRPT1xxxx...==</key></result></response>
```
→ extraire **uniquement** le contenu entre `<key>` et `</key>`, et `trim()`
(pas les balises, pas d'espace/retour-ligne).

---

## 2. Récupérer les OBJETS ADRESSES

| | |
|---|---|
| **Method** | `GET` |
| **Endpoint** | `https://<panorama>/api/` |
| **Query params** | `type=config` · `action=get` · `xpath=/config/shared/address` |
| **Header** | `X-PAN-KEY: <clé API>` ← **recommandé** (évite le 403) |
| **Body** | *(aucun)* |

**URL complète (clé en header) :**
```
https://gdcpamgmt002.dir.ucb-group.com/api/?type=config&action=get&xpath=/config/shared/address
```

**Réponse (XML) :**
```xml
<response status="success"><result>
  <address>
    <entry name="net-10.1.0.0_16"><ip-netmask>10.1.0.0/16</ip-netmask></entry>
    <entry name="host-x"><ip-range>10.1.1.1-10.1.1.5</ip-range></entry>
    <entry name="srv-fqdn"><fqdn>server.ucb.com</fqdn></entry>
  </address>
</result></response>
```

**Mapping des champs :**
| Balise | Sens |
|--------|------|
| `entry name="..."` | nom de l'objet |
| `<ip-netmask>` | IP ou sous-réseau (ex. `10.1.0.0/16`) |
| `<ip-range>` | plage (ex. `10.1.1.1-10.1.1.5`) |
| `<fqdn>` | nom DNS (ex. `server.ucb.com`) |

> ⚠️ `/config/shared/address` est **volumineux** (~28994 objets) → grosse
> réponse XML, un seul appel. Prévoir un timeout large côté ServiceNow.

---

## 3. Récupérer les GROUPES D'ADRESSES

| | |
|---|---|
| **Method** | `GET` |
| **Endpoint** | `https://<panorama>/api/` |
| **Query params** | `type=config` · `action=get` · `xpath=/config/shared/address-group` |
| **Header** | `X-PAN-KEY: <clé API>` |
| **Body** | *(aucun)* |

**Réponse (XML) :**
```xml
<response status="success"><result>
  <address-group>
    <entry name="GRP-SAP-RISE">
      <static>
        <member>net-10.120.0.0_22</member>
        <member>net-10.120.4.0_22</member>
      </static>
    </entry>
    <entry name="GRP-DYN">
      <dynamic><filter>'tag1' and 'tag2'</filter></dynamic>
    </entry>
  </address-group>
</result></response>
```

**Mapping :**
| Balise | Sens |
|--------|------|
| `<static><member>` | groupe **statique** : liste des objets membres |
| `<dynamic><filter>` | groupe **dynamique** : filtre par tags (pas de membres fixes) |

---

## 4. Variantes utiles

**Objets d'un DEVICE-GROUP (au lieu du shared) :**
```
xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='<NOM_DG>']/address
xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='<NOM_DG>']/address-group
```

**Un objet / groupe PRÉCIS par nom :**
```
xpath=/config/shared/address/entry[@name='net-10.1.0.0_16']
xpath=/config/shared/address-group/entry[@name='GRP-SAP-RISE']
```

> 💡 Le **shared complet** est sur Panorama (ne pas mettre `target`). Ajouter
> `&target=<serial>` donne la vue partielle d'un firewall.

---

## 5. Récapitulatif des appels

| # | But | Method | Query params | Header clé |
|---|-----|--------|--------------|------------|
| 1 | Clé API | GET | `type=keygen&user=&password=` | — |
| 2 | Objets adresses | GET | `type=config&action=get&xpath=/config/shared/address` | `X-PAN-KEY` |
| 3 | Groupes | GET | `type=config&action=get&xpath=/config/shared/address-group` | `X-PAN-KEY` |

---

## 6. Exemple ServiceNow (RESTMessageV2)

```javascript
var BASE = 'https://gdcpamgmt002.dir.ucb-group.com/api/';
var MID  = 'nom_de_ton_mid_server';   // Panorama est en IP interne

// --- 1. KEYGEN ---
var kg = new sn_ws.RESTMessageV2();
kg.setEndpoint(BASE + '?type=keygen&user=apisnow&password=' + encodeURIComponent(PASSWORD));
kg.setHttpMethod('GET');
kg.setMIDServer(MID);
var kgResp = kg.execute();
var apiKey = kgResp.getBody().match(/<key>(.*?)<\/key>/)[1].trim();   // clé nettoyée

// --- 2. OBJETS ADRESSES ---
var rm = new sn_ws.RESTMessageV2();
rm.setEndpoint(BASE + '?type=config&action=get&xpath=' +
               encodeURIComponent('/config/shared/address'));
rm.setHttpMethod('GET');
rm.setMIDServer(MID);
rm.setRequestHeader('X-PAN-KEY', apiKey);      // clé en header -> pas de 403
var resp = rm.execute();
gs.info(resp.getStatusCode());
gs.info(resp.getBody());                        // XML <address>...</address>

// --- 3. GROUPES (meme principe) ---
// xpath = '/config/shared/address-group'
```

**Points clés du script :**
- `encodeURIComponent` sur le **password** (keygen) et sur le **xpath** (contient des `/` et `[]`).
- clé API en **header `X-PAN-KEY`** (jamais dans l'URL sans encodage).
- `setMIDServer` car Panorama est en IP interne.
- clé **trim()** après extraction (pas d'espace/balise).

---

## 7. Équivalent curl (pour tester/débugger)

```bash
# 1. clé
curl -k "https://gdcpamgmt002.dir.ucb-group.com/api/?type=keygen&user=apisnow&password=MDP"

# 2. objets adresses (clé en header)
curl -k -H "X-PAN-KEY: LA_CLE" \
  "https://gdcpamgmt002.dir.ucb-group.com/api/?type=config&action=get&xpath=/config/shared/address"

# 3. groupes
curl -k -H "X-PAN-KEY: LA_CLE" \
  "https://gdcpamgmt002.dir.ucb-group.com/api/?type=config&action=get&xpath=/config/shared/address-group"
```

---

## 8. Dépannage (erreurs rencontrées)

| Erreur | Cause | Solution |
|--------|-------|----------|
| `400 Missing value for parameter "type"` | params pas transmis | tout dans l'URL, ou POST form-urlencoded |
| `403 Invalid Credential` | clé mal encodée (`+`/`/`/`=`) | clé en header `X-PAN-KEY` (ou URL-encoder) ; ne pas double-encoder |
| `403 Invalid Credential` (persiste) | clé tronquée / avec espace / compte sans droit API | extraire `<key>` + trim ; vérifier rôle admin "XML API" du compte |
| `Connection refused` / timeout | Panorama en IP interne non joignable | passer par un **MID Server** sur le réseau interne |
| réponse vide / partielle | `target=<serial>` (vue firewall) | interroger Panorama sans `target` pour le shared complet |

---

## 9. Référence : le script Python qui fait tout ça

`scripts/get_panorama_objects.py` (réutilise `scripts/panorama_client.py`) :
```bash
python scripts/get_panorama_objects.py --csv objets.csv --json objets.json
python scripts/get_panorama_objects.py --dg "NewMed - GDC" --json objets_dg.json
```
Sortie validée : **28994 objets adresses + 622 groupes** (shared).
