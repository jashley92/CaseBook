# Embedded MITRE ATT&CK catalogue

`attack-techniques.json` is the compact ATT&CK **Enterprise v19.1** technique catalogue that powers
the technique picker (`AttackTechniquePicker`) via `AttackCatalog`. It is generated reference data —
edit the generator, not the JSON by hand. It's an embedded resource (see the `.csproj`), so the app
carries it with no network or DB dependency (the deployment is on-prem / air-gapped).

Each entry: `{ id, name, tactics[], sub }` — `tactics` are `MitreTactic` enum member names in ATT&CK
matrix order (so `tactics[0]` is the primary), `sub` marks a sub-technique. Revoked and deprecated
techniques are dropped.

## Refreshing to a newer ATT&CK version

1. Download the official STIX bundle `enterprise-attack.json` (not committed; ~50 MB) from
   <https://github.com/mitre-attack/attack-stix-data> or attack.mitre.org.
2. Regenerate:

   ```bash
   node generate-catalog.mjs /path/to/enterprise-attack.json
   ```

3. Bump `AttackCatalog.Version`.
4. **If the new version renamed or added tactics**, the script fails with the unmapped shortname(s).
   Reconcile before regenerating: update the `TACTIC`/`RANK` maps in `generate-catalog.mjs`,
   `Domain/Enums/MitreEnums.cs` (append new members — never renumber; values are stored and hashed),
   and `Web/Components/Shared/Ui.cs` (`Label`/`TacticId`/`TacticGlyph`/`TacticColor`/
   `TacticDescription`/`TacticRank`).

> v19.1 note: ATT&CK renamed **TA0005 "Defense Evasion" → "Stealth"** (the enum keeps value `7`, so
> existing tagged data and tamper hashes are unaffected) and added **TA0112 "Defense Impairment"**.
