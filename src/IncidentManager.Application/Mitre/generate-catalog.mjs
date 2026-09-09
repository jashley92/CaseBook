// Regenerates attack-techniques.json (the embedded ATT&CK technique catalogue) from an official
// MITRE ATT&CK Enterprise STIX bundle. Run this when bumping to a newer ATT&CK version.
//
//   node generate-catalog.mjs <path-to-enterprise-attack.json>
//
// The STIX bundle is large (~50 MB) and is NOT committed; download it from
// https://github.com/mitre-attack/attack-stix-data (enterprise-attack/…) or attack.mitre.org.
// Output: attack-techniques.json next to this script (compact, ~60 KB), embedded via the .csproj.
//
// Tactic names are emitted as MitreTactic enum member names, so if ATT&CK renames/adds tactics you
// must also update Domain/Enums/MitreEnums.cs, Web/Components/Shared/Ui.cs (label/id/glyph/colour/
// description + TacticRank), and AttackCatalog.Version. This script fails loudly on an unmapped tactic.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const input = process.argv[2];
if (!input) {
  console.error('usage: node generate-catalog.mjs <path-to-enterprise-attack.json>');
  process.exit(1);
}

// ATT&CK tactic shortname -> MitreTactic enum member (must match Domain/Enums/MitreEnums.cs).
const TACTIC = {
  'reconnaissance': 'Reconnaissance',
  'resource-development': 'ResourceDevelopment',
  'initial-access': 'InitialAccess',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'PrivilegeEscalation',
  'stealth': 'Stealth',                 // TA0005 (formerly "Defense Evasion", renamed in v19).
  'defense-impairment': 'DefenseImpairment', // TA0112 (added in v19).
  'credential-access': 'CredentialAccess',
  'discovery': 'Discovery',
  'lateral-movement': 'LateralMovement',
  'collection': 'Collection',
  'command-and-control': 'CommandAndControl',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact',
};

// Matrix order, used to sort a technique's tactics so the first is its primary.
const RANK = {
  Reconnaissance: 1, ResourceDevelopment: 2, InitialAccess: 3, Execution: 4, Persistence: 5,
  PrivilegeEscalation: 6, Stealth: 7, DefenseImpairment: 8, CredentialAccess: 9, Discovery: 10,
  LateralMovement: 11, Collection: 12, CommandAndControl: 13, Exfiltration: 14, Impact: 15,
};

const bundle = JSON.parse(readFileSync(input, 'utf8'));
const unmapped = new Set();
const out = [];

for (const o of bundle.objects) {
  if (o.type !== 'attack-pattern' || o.revoked || o.x_mitre_deprecated) continue;
  const ext = (o.external_references || []).find(r => r.source_name === 'mitre-attack' && /^T\d/.test(r.external_id));
  if (!ext) continue;

  const tactics = [...new Set((o.kill_chain_phases || [])
    .filter(p => p.kill_chain_name === 'mitre-attack')
    .map(p => { const m = TACTIC[p.phase_name]; if (!m) unmapped.add(p.phase_name); return m; })
    .filter(Boolean))].sort((a, b) => RANK[a] - RANK[b]);

  out.push({ id: ext.external_id, name: o.name, tactics, sub: !!o.x_mitre_is_subtechnique });
}

if (unmapped.size > 0) {
  console.error('ERROR: unmapped ATT&CK tactic shortname(s):', [...unmapped],
    '\nUpdate the TACTIC/RANK maps here and the MitreTactic enum + Ui before regenerating.');
  process.exit(1);
}

out.sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));

const outPath = join(dirname(fileURLToPath(import.meta.url)), 'attack-techniques.json');
writeFileSync(outPath, JSON.stringify(out));
console.log(`wrote ${out.length} techniques (${out.filter(x => x.sub).length} sub) -> ${outPath}`);
