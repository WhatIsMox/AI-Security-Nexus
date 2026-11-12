/**
 * Unit/Build-contract Tests — MITRE ATLAS lightweight index, de-duplicated catalog,
 * lazy-loading contract (keeps the multi-megabyte dataset off the critical path),
 * and the CSP hash plugin for the inline analytics loader.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { transformSync } from 'esbuild';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (rel) => fs.readFileSync(path.join(rootDir, rel), 'utf8');

const load = async (rel, stub = {}) => {
  let { code } = transformSync(read(rel), { loader: 'ts', format: 'esm', target: 'es2022' });
  code = code.replace(/^import .*from ['"]\.\.\/types['"];?$/m, '');
  return import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
};

const full = await load('src/data/data_mitre_atlas.ts');
const index = await load('src/data/data_mitre_atlas_index.ts');

test('ATLAS index - covers exactly the techniques of the full catalog', () => {
  const fullIds = full.MITRE_ATLAS_TECHNIQUES.map((t) => t.id);
  const idxIds = index.MITRE_ATLAS_TECHNIQUE_INDEX.map((t) => t.id);
  assert.deepEqual(idxIds, fullIds);
  assert.equal(new Set(fullIds).size, fullIds.length, 'technique IDs must be unique');
  assert.deepEqual(index.MITRE_ATLAS_SUMMARY, full.MITRE_ATLAS_META, 'summary must mirror META');
  assert.equal(index.MITRE_ATLAS_SUMMARY.totalTechniques, fullIds.length);
  for (const e of index.MITRE_ATLAS_TECHNIQUE_INDEX) {
    assert.ok(e.name && e.tacticName, `${e.id} needs name and tactic`);
  }
});

test('ATLAS catalog - tactics are re-hydrated from IDs with shared technique objects', () => {
  assert.equal(full.MITRE_ATLAS_TACTICS.length, 16);
  const byId = new Map(full.MITRE_ATLAS_TECHNIQUES.map((t) => [t.id, t]));
  let linked = 0;
  for (const tactic of full.MITRE_ATLAS_TACTICS) {
    assert.ok(Array.isArray(tactic.techniques), `${tactic.id} techniques`);
    assert.equal('techniqueIds' in tactic, false, 'raw ID list must not leak into the public shape');
    for (const t of tactic.techniques) {
      assert.equal(t, byId.get(t.id), `${tactic.id} must reference the canonical ${t.id} object`);
      linked++;
    }
  }
  assert.ok(linked >= full.MITRE_ATLAS_TECHNIQUES.length / 2);
  assert.equal(full.MITRE_ATLAS_OVERVIEW.tactics, full.MITRE_ATLAS_TACTICS);
});

test('ATLAS catalog - every ATLAS ref used by the catalogs resolves to a current technique', () => {
  const valid = new Set(full.MITRE_ATLAS_TECHNIQUES.map((t) => t.id));
  for (const f of ['data_tests', 'data_llm', 'data_mcp', 'data_saif', 'data_genai_data_security', 'data_agentic', 'data_agentic_applications', 'data_ml']) {
    for (const m of read(`src/data/${f}.ts`).matchAll(/AML\.T\d{4}(?:\.\d{3})?/g)) {
      assert.ok(valid.has(m[0]), `${f}.ts references unknown ATLAS technique ${m[0]}`);
    }
  }
});

test('Loading contract - first-paint views use the light index; the full dataset is lazy', () => {
  for (const f of ['src/components/Dashboard.tsx', 'src/components/TestList.tsx', 'src/App.tsx']) {
    const src = read(f);
    assert.ok(!/from ['"]\.\.?\/(?:data\/)?data_mitre_atlas['"]/.test(src), `${f} must not statically import the full ATLAS dataset`);
    assert.ok(!/\bMITRE_ATLAS_(TECHNIQUES|TACTICS)\b/.test(src), `${f} must not use the heavy ATLAS arrays`);
  }
  const search = read('src/components/GlobalSearchModal.tsx');
  assert.ok(search.includes("import('../data/data_mitre_atlas')"), 'Global search must load full ATLAS lazily');
  assert.ok(search.includes('data_mitre_atlas_index'), 'Global search must use the index immediately');

  const vite = read('vite.config.ts');
  assert.ok(vite.includes('moduleSideEffects'), 'Data modules must be declared side-effect free');
  assert.ok(vite.includes("!id.includes('data_mitre_atlas_index')"), 'The light index must not be bundled into the heavy ATLAS chunk');
  assert.ok(vite.includes('catalog-data'), 'Static catalogs must live in their own cacheable chunk');
});

test('ATLAS sync - workflow commits both generated files and generator emits the index', () => {
  const wf = read('.github/workflows/mitre-atlas-sync.yml');
  assert.ok(wf.includes('src/data/data_mitre_atlas_index.ts'));
  const gen = read('scripts/sync-mitre-atlas.mjs');
  assert.ok(gen.includes('generateIndexFile') && gen.includes('OUTPUT_INDEX_FILE'));
});

test('CSP - inline analytics loader is allowed by SHA-256 hash, never by unsafe-inline in production', async () => {
  const vite = read('vite.config.ts');
  assert.ok(vite.includes('inlineScriptHashes') && vite.includes("createHash('sha256')"));
  const prod = vite.slice(vite.indexOf('const scriptSrc'), vite.indexOf('const connectSrc'));
  const [dev, prodBranch] = prod.split('\n: ');
  assert.ok(/unsafe-inline/.test(dev) && !/unsafe-inline/.test(prodBranch ?? ''), "'unsafe-inline' only allowed in dev");

  // Same regex/hash as the plugin, applied to the real index.html
  const html = read('index.html');
  const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1]).filter((b) => b.trim());
  assert.equal(scripts.length, 1, 'index.html must contain exactly the analytics loader as inline script');
  assert.ok(scripts[0].includes('loadAnalytics'));
});
