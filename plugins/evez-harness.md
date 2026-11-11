# evezHarness — OSINT amplification plugin

One input, many independent checks, each carrying the falsifier that would overturn it.
No LLM in the loop. No paid APIs. Deterministic sources only.

**Endpoint**

```
POST https://cipher-copy-copy-20f1d98a.base44.app/functions/evezHarness
Content-Type: application/json

{"target": "github.com"}
```

GET also works: `?target=...`

**Accepted target types** (auto-detected): domain, IPv4, TRON address (`T...`, 34 chars), ETH address (`0x` + 40 hex), BTC address (legacy or bech32).

**Response shape**

```json
{
  "ok": true,
  "target": "TU4tDFRvcKhAZ1jdihojmBWZqvJhQCnJ4F",
  "kind": "tron",
  "checks_run": 2,
  "checks_succeeded": 2,
  "verdict": "COMPLETE",
  "findings": [
    {"check": "tron_account", "ok": true, "value": {"trx": 423.307658, "trc20": 6, "created_ms": 1677523050000},
     "falsifier": "Falsified if TronGrid returns a different balance at the same block."},
    {"check": "sanctions_screen", "ok": true, "value": "Aeza Group (OFAC-designated)",
     "falsifier": "Falsified only by an OFAC SDN query; the local list is not authoritative."}
  ],
  "limitation": "Every check names the independent source that would overturn it. None is conjunctive proof."
}
```

**Checks by target type**

| target | checks |
|---|---|
| domain | `dns_a` (Cloudflare DoH), `rdap_domain` (Verisign, fallback rdap.org) |
| IPv4 | `rdap_ip` (ARIN, fallback rdap.org) — currently returns NO_DATA from the function runtime, see Limitations |
| TRON | `tron_account` (TronGrid: TRX balance, TRC20 position count, account creation) |
| ETH | `eth_balance` (public RPC, wei) |
| BTC | `btc_balance` (Blockstream: confirmed sats, tx count) |
| all | `sanctions_screen` against the local designation list |

**How Hermes consumes it**

The value is the falsifier field. A finding without a named disproof source is a rumour, not evidence.
Ingest rule: report `check`, `value`, and `falsifier` together. Never strip the falsifier to make a
finding read more cleanly, and never merge findings into a single verdict sentence that hides a MISS.

Minimal skill wrapper:

```bash
evez_harness() {
  curl -s -m 45 -X POST \
    https://cipher-copy-copy-20f1d98a.base44.app/functions/evezHarness \
    -H 'Content-Type: application/json' \
    -d "{\"target\":\"$1\"}"
}
```

**Limitations (stated, not hidden)**

- IP RDAP fails from the function runtime (ARIN reachable from the sandbox, not from Deno). IP targets therefore return `NO_DATA` unless a fallback source is added.
- The sanctions list is a local two-entry list, not an OFAC SDN query. It can only ever confirm a match in our own records, never clear a target.
- `checks_succeeded < checks_run` is normal and is information, not failure. A MISS means that source did not answer, which is different from a negative finding.
- No check here is proof of wrongdoing, ownership, or intent. Attribution requires evidence outside this tool.

**Doctrine alignment**

Every finding is falsifiable by a named external source. That is the entire point of the instrument:
it makes denial cheap and verification concrete, which is what a defensible dossier requires.
