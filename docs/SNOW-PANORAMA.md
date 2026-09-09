# ServiceNow → Panorama Integration (PAN-OS XML API)

Reference documentation to retrieve **address objects** and **address groups**
from Panorama via the PAN-OS XML API, from ServiceNow.

Based on the validated script `scripts/get_panorama_objects.py`.

---

## Environments

| Environment | Base URL |
|-------------|----------|
| **Production** | `https://gdcpamgmt002.dir.ucb-group.com/` |
| **Development** | `https://10.15.95.100/` |

> All API calls use the base path `<Base URL>api/` — **keep the trailing `/`
> before `?`** (e.g. `.../api/?type=...`).

---

## 0. Fundamentals (READ FIRST)

| Item | Detail |
|------|--------|
| **Protocol** | PAN-OS XML API (responses are **XML**, not JSON) |
| **Base URL** | `https://<panorama>/api/` |
| **Method** | `GET` (parameters go in the query string; no body) |
| **Authentication** | **API key** (generated once), NO session cookie |
| **Network** | Panorama is on an internal IP → from ServiceNow cloud, route through a **MID Server** |
| **TLS/SSL** | internal certificate → import it into the keystore, or use a MID Server that trusts it |

### ⚠️ The 2 pitfalls that cause 99% of errors

1. **`400 Missing value for parameter "type"`**
   → parameters are not reaching Panorama. Put **all parameters in the URL**
   (`/api/?type=...&...`), or use a POST form-urlencoded request.
   URL-encode the password if it contains special characters (`&`, `#`, `+`, …).

2. **`403 Invalid Credential` even though the key looks correct**
   → the **API key is being transmitted incorrectly**. PAN-OS keys contain
   `+`, `/`, `=` which get **corrupted in a query string** (`+` becomes a space).
   **Fix: send the key in the `X-PAN-KEY` header** (no encoding needed),
   OR URL-encode it (`+`→`%2B`, `/`→`%2F`, `=`→`%3D`).
   NEVER double-encode (do not `quote()` then let the HTTP client re-encode).

---

## 1. Generate the API key (once, or to refresh)

| | |
|---|---|
| **Method** | `GET` |
| **Endpoint** | `https://<panorama>/api/` |
| **Query params** | `type=keygen` · `user=<user>` · `password=<password>` |
| **Headers** | *(none)* |
| **Body** | *(none)* |

**Full URL (Prod):**
```
https://gdcpamgmt002.dir.ucb-group.com/api/?type=keygen&user=apisnow&password=<ENCODED_PASSWORD>
```

> If the password contains special characters, URL-encode it, OR prefer a **POST**
> form-urlencoded request:
> ```
> POST https://<panorama>/api/
> Content-Type: application/x-www-form-urlencoded
> Body: type=keygen&user=apisnow&password=<PASSWORD>
> ```

**Response (XML):**
```xml
<response status="success"><result><key>LUFRPT1xxxx...==</key></result></response>
```
→ extract **only** the content between `<key>` and `</key>`, and `trim()` it
(no tags, no leading/trailing whitespace or newline).

---

## 2. Retrieve ADDRESS OBJECTS

| | |
|---|---|
| **Method** | `GET` |
| **Endpoint** | `https://<panorama>/api/` |
| **Query params** | `type=config` · `action=get` · `xpath=/config/shared/address` |
| **Header** | `X-PAN-KEY: <api key>` ← **recommended** (prevents the 403) |
| **Body** | *(none)* |

**Full URL (Prod):**
```
https://gdcpamgmt002.dir.ucb-group.com/api/?type=config&action=get&xpath=/config/shared/address
```

**Response (XML):**
```xml
<response status="success"><result>
  <address>
    <entry name="net-10.1.0.0_16"><ip-netmask>10.1.0.0/16</ip-netmask></entry>
    <entry name="host-x"><ip-range>10.1.1.1-10.1.1.5</ip-range></entry>
    <entry name="srv-fqdn"><fqdn>server.ucb.com</fqdn></entry>
  </address>
</result></response>
```

**Field mapping:**
| Tag | Meaning |
|-----|---------|
| `entry name="..."` | object name |
| `<ip-netmask>` | IP or subnet (e.g. `10.1.0.0/16`) |
| `<ip-range>` | range (e.g. `10.1.1.1-10.1.1.5`) |
| `<fqdn>` | DNS name (e.g. `server.ucb.com`) |

> ⚠️ `/config/shared/address` is **large** (~28,994 objects) → big XML response,
> single call. Use a generous timeout on the ServiceNow side.

---

## 3. Retrieve ADDRESS GROUPS

| | |
|---|---|
| **Method** | `GET` |
| **Endpoint** | `https://<panorama>/api/` |
| **Query params** | `type=config` · `action=get` · `xpath=/config/shared/address-group` |
| **Header** | `X-PAN-KEY: <api key>` |
| **Body** | *(none)* |

**Response (XML):**
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

**Mapping:**
| Tag | Meaning |
|-----|---------|
| `<static><member>` | **static** group: list of member objects |
| `<dynamic><filter>` | **dynamic** group: tag-based filter (no fixed members) |

---

## 4. Useful variants

**Objects of a DEVICE-GROUP (instead of shared):**
```
xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='<DG_NAME>']/address
xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='<DG_NAME>']/address-group
```

**A SINGLE object / group by name:**
```
xpath=/config/shared/address/entry[@name='net-10.1.0.0_16']
xpath=/config/shared/address-group/entry[@name='GRP-SAP-RISE']
```

> 💡 The **full shared config** lives on Panorama (do NOT add `target`). Adding
> `&target=<serial>` returns the partial view of a single firewall.

---

## 5. Call summary

| # | Purpose | Method | Query params | Key header |
|---|---------|--------|--------------|------------|
| 1 | API key | GET | `type=keygen&user=&password=` | — |
| 2 | Address objects | GET | `type=config&action=get&xpath=/config/shared/address` | `X-PAN-KEY` |
| 3 | Address groups | GET | `type=config&action=get&xpath=/config/shared/address-group` | `X-PAN-KEY` |

---

## 6. ServiceNow example (RESTMessageV2)

```javascript
// Production base URL (Dev: https://10.15.95.100/api/)
var BASE = 'https://gdcpamgmt002.dir.ucb-group.com/api/';
var MID  = 'your_mid_server';   // Panorama is on an internal IP

// --- 1. KEYGEN ---
var kg = new sn_ws.RESTMessageV2();
kg.setEndpoint(BASE + '?type=keygen&user=apisnow&password=' + encodeURIComponent(PASSWORD));
kg.setHttpMethod('GET');
kg.setMIDServer(MID);
var kgResp = kg.execute();
var apiKey = kgResp.getBody().match(/<key>(.*?)<\/key>/)[1].trim();   // cleaned key

// --- 2. ADDRESS OBJECTS ---
var rm = new sn_ws.RESTMessageV2();
rm.setEndpoint(BASE + '?type=config&action=get&xpath=' +
               encodeURIComponent('/config/shared/address'));
rm.setHttpMethod('GET');
rm.setMIDServer(MID);
rm.setRequestHeader('X-PAN-KEY', apiKey);      // key in header -> no 403
var resp = rm.execute();
gs.info(resp.getStatusCode());
gs.info(resp.getBody());                        // XML <address>...</address>

// --- 3. ADDRESS GROUPS (same pattern) ---
// xpath = '/config/shared/address-group'
```

**Key points:**
- `encodeURIComponent` on the **password** (keygen) and on the **xpath** (it contains `/` and `[]`).
- API key in the **`X-PAN-KEY` header** (never in the URL without encoding).
- `setMIDServer` because Panorama is on an internal IP.
- `trim()` the key after extraction (no whitespace/tags).

---

## 7. curl equivalent (for testing/debugging)

```bash
# 1. key
curl -k "https://gdcpamgmt002.dir.ucb-group.com/api/?type=keygen&user=apisnow&password=PASSWORD"

# 2. address objects (key in header)
curl -k -H "X-PAN-KEY: THE_KEY" \
  "https://gdcpamgmt002.dir.ucb-group.com/api/?type=config&action=get&xpath=/config/shared/address"

# 3. groups
curl -k -H "X-PAN-KEY: THE_KEY" \
  "https://gdcpamgmt002.dir.ucb-group.com/api/?type=config&action=get&xpath=/config/shared/address-group"
```

---

## 8. Troubleshooting (errors encountered)

| Error | Cause | Fix |
|-------|-------|-----|
| `400 Missing value for parameter "type"` | params not transmitted | put everything in the URL, or POST form-urlencoded |
| `403 Invalid Credential` | key badly encoded (`+`/`/`/`=`) | key in `X-PAN-KEY` header (or URL-encode); never double-encode |
| `403 Invalid Credential` (persists) | key truncated / has whitespace / account lacks API rights | extract `<key>` + trim; verify the account's admin role has "XML API" enabled |
| `Connection refused` / timeout | Panorama on internal IP not reachable | route through a **MID Server** on the internal network |
| empty / partial response | `target=<serial>` (firewall view) | query Panorama without `target` for the full shared config |

---

## 9. Reference: the Python script

`scripts/get_panorama_objects.py` (reuses `scripts/panorama_client.py`):
```bash
python scripts/get_panorama_objects.py --csv objects.csv --json objects.json
python scripts/get_panorama_objects.py --dg "NewMed - GDC" --json objects_dg.json
```
Validated output (Production shared): **28,994 address objects + 622 groups**.
