import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../..');

function readFile(relativePath) {
  let fullPath = path.join(rootDir, relativePath);
  if (!fs.existsSync(fullPath)) {
    if (fs.existsSync(path.join(rootDir, 'src/data', relativePath))) {
      fullPath = path.join(rootDir, 'src/data', relativePath);
    } else if (fs.existsSync(path.join(rootDir, 'src/components', relativePath))) {
      fullPath = path.join(rootDir, 'src/components', relativePath);
    } else if (fs.existsSync(path.join(rootDir, 'src', relativePath))) {
      fullPath = path.join(rootDir, 'src', relativePath);
    }
  }
  return fs.readFileSync(fullPath, 'utf8');
}

test('Unit - MITRE ATLAS Catalog Schema & Structure', () => {
  const content = readFile('data_mitre_atlas.ts');
  assert.ok(content.length > 1000, 'data_mitre_atlas.ts must exist and be non-empty');

  // Verify exports
  assert.ok(content.includes('export const MITRE_ATLAS_META'), 'Must export MITRE_ATLAS_META');
  assert.ok(content.includes('export const MITRE_ATLAS_TACTICS'), 'Must export MITRE_ATLAS_TACTICS');
  assert.ok(content.includes('export const MITRE_ATLAS_TECHNIQUES'), 'Must export MITRE_ATLAS_TECHNIQUES');
  assert.ok(content.includes('export const MITRE_ATLAS_OVERVIEW'), 'Must export MITRE_ATLAS_OVERVIEW');

  // Verify tactics count
  const tacticMatches = [...content.matchAll(/"?id"?:\s*["'](AML\.TA\d{4})["']/g)].map(m => m[1]);
  const uniqueTactics = new Set(tacticMatches);
  assert.equal(uniqueTactics.size, 16, 'Expected exactly 16 official MITRE ATLAS tactics (AML.TA0000-AML.TA0015)');

  // Verify techniques count
  const techMatches = [...content.matchAll(/"?id"?:\s*["'](AML\.T\d{4}(?:\.\d{3})?)["']/g)].map(m => m[1]);
  const uniqueTechs = new Set(techMatches);
  assert.ok(uniqueTechs.size >= 50, `Expected at least 50 unique MITRE ATLAS techniques, found ${uniqueTechs.size}`);
});

test('Unit - MITRE ATLAS Freshness & Upstream Synchronization Metadata', () => {
  const content = readFile('data_mitre_atlas.ts');

  // Verify metadata properties
  const versionMatch = content.match(/"?version"?:\s*["']([^"']+)["']/);
  const lastUpdatedMatch = content.match(/"?lastUpdated"?:\s*["'](\d{4}-\d{2}-\d{2})["']/);

  assert.ok(versionMatch, 'MITRE ATLAS must define version metadata');
  assert.ok(lastUpdatedMatch, 'MITRE ATLAS must define lastUpdated date in YYYY-MM-DD format');

  const lastUpdatedDate = new Date(lastUpdatedMatch[1]);
  assert.ok(!isNaN(lastUpdatedDate.getTime()), 'lastUpdated must be a valid date');
  
  // Ensure sync script exists
  const syncScriptPath = path.join(rootDir, 'scripts/sync-mitre-atlas.mjs');
  assert.ok(fs.existsSync(syncScriptPath), 'scripts/sync-mitre-atlas.mjs must exist');
});

test('Unit - Security Tests & Framework Cross-References to MITRE ATLAS Techniques', () => {
  const atlasContent = readFile('data_mitre_atlas.ts');
  const validAtlasIds = new Set([...atlasContent.matchAll(/"?id"?:\s*["'](AML\.T\d{4}(?:\.\d{3})?)["']/g)].map(m => m[1]));

  const frameworkFiles = [
    'data_tests.ts',
    'data_llm.ts',
    'data_agentic_applications.ts',
    'data_agentic.ts',
    'data_mcp.ts',
    'data_ml.ts',
    'data_saif.ts',
    'data_genai_data_security.ts',
  ];

  for (const file of frameworkFiles) {
    const content = readFile(file);
    const refs = [
      ...[...content.matchAll(/mitreAtlasRef:\s*["']([^"']+)["']/g)].map(m => m[1]),
      ...[...content.matchAll(/["'](AML\.T\d{4}(?:\.\d{3})?)["']/g)].map(m => m[1])
    ];

    assert.ok(refs.length > 0, `${file} must contain cross-references to MITRE ATLAS techniques`);
    for (const ref of refs) {
      if (ref.startsWith('AML.T')) {
        assert.ok(validAtlasIds.has(ref), `${file} references unknown MITRE ATLAS technique ID: "${ref}"`);
      }
    }
  }
});

test('Unit - MITRE ATLAS 1-to-1 Parity: Procedure Examples & Specific Mitigations', () => {
  const atlasContent = readFile('data_mitre_atlas.ts');

  // Verify procedure examples
  const procedureMatches = (atlasContent.match(/"caseStudyId":\s*"AML\.CS\d{4}"/g) || []).length;
  assert.ok(procedureMatches >= 200, `Expected at least 200 procedure examples, found ${procedureMatches}`);

  // Verify specific mitigation guidance (useDescription)
  const useDescMatches = (atlasContent.match(/"useDescription":/g) || []).length;
  assert.ok(useDescMatches >= 100, `Expected at least 100 specific mitigation useDescription entries, found ${useDescMatches}`);

  // Verify ATT&CK references
  const attackRefMatches = (atlasContent.match(/"attackReference":/g) || []).length;
  assert.ok(attackRefMatches >= 50, `Expected at least 50 ATT&CK references, found ${attackRefMatches}`);

  // Verify benchmark technique AML.T0006
  assert.ok(atlasContent.includes('"id": "AML.T0006"'), 'AML.T0006 must be present in catalog');
  assert.ok(atlasContent.includes('Active Scanning'), 'AML.T0006 name must be Active Scanning');
  assert.ok(atlasContent.includes('AML.CS0023'), 'AML.T0006 must link to ShadowRay case study (AML.CS0023)');
  assert.ok(atlasContent.includes('AML.M0019'), 'AML.T0006 must link to AML.M0019 mitigation');
});
