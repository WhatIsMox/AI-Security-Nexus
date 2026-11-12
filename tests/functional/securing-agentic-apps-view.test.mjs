/**
 * Functional & Integrity Tests — OWASP Securing Agentic Applications V2 (October 2026)
 *
 * The data module and the read-progress sanitizer are compiled with esbuild (shipped
 * with Vite) and executed, so these tests assert real runtime values — not just regex
 * matches — for chapter coverage, referential integrity, widget wiring, routing, and
 * storage hardening.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { transformSync } from 'esbuild';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../..');

const read = (rel) => fs.readFileSync(path.join(rootDir, rel), 'utf8');

async function loadTsModule(rel) {
  const { code } = transformSync(read(rel), { loader: 'ts', format: 'esm', target: 'es2022' });
  return import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
}

const saa = await loadTsModule('src/data/data_securing_agentic_apps.ts');
const progress = await loadTsModule('src/components/securing-agentic/readProgress.ts');

// ─── 1. Coverage of the source guide ─────────────────────────────────────────

test('SAA data - covers chapters 1–9 plus the acknowledgements appendix', () => {
  const numbers = saa.SAA_CHAPTERS.map((c) => c.number);
  assert.deepEqual(numbers, ['1', '2', '3', '4', '5', '6', '7', '8', '9', 'A']);
  for (const ch of saa.SAA_CHAPTERS) {
    assert.match(ch.id, /^SAA-(CH\d|ACK)$/);
    assert.ok(ch.title.length > 5 && ch.tagline.length > 20, `${ch.id} needs title & tagline`);
    assert.ok(ch.sections.length > 0, `${ch.id} must contain sections`);
  }
});

test('SAA data - every numbered subsection of the guide is present', () => {
  const ids = new Set(saa.SAA_ALL_SECTIONS.map((s) => s.id));
  const required = [
    '1.1', '1.2', '1.3', '2.1', '2.2', '2.3.1', '2.3.2', '2.4', '2.5', '2.6', '2.7.1', '2.7.2', '2.7.3',
    '3.1.1', '3.1.2', '3.1.3', '3.1.4', '3.1.5', '3.1.6', '3.1.7', '3.1.8',
    '3.2.1', '3.2.2', '3.2.3', '3.2.4', '3.2.5',
    '3.3.1', '3.3.2', '3.3.3', '3.3.4', '3.3.5', '3.3.6', '3.3.7', '3.3.8',
    '4.1.1', '4.1.2', '4.1.3', '4.1.4', '4.1.5', '4.2.1', '4.2.2', '4.2.3', '4.2.4', '4.3.1', '4.3.2', '4.3.3', '4.4',
    '5.0', '5.1', '5.2', '5.3', '5.4', '5.5', '5.5.1', '5.6',
    '6.1.1', '6.1.2', '6.2.1', '6.2.2', '6.2.3', '6.3.1', '6.3.2', '6.4.1', '6.4.2', '6.4.3', '6.4.4', '6.4.5',
    '7.0', '7.0.1', '7.0.2', '7.0.3', '7.0.4', '7.0.5', '7.1', '7.2', '7.2.1', '7.2.2', '7.2.3',
    '9.1', '9.2', '9.3', '9.4', '9.5', '9.6', '9.7',
  ];
  for (const n of required) assert.ok(ids.has(`SAA-${n}`), `Missing section SAA-${n}`);
  const ch8 = saa.SAA_CHAPTERS.find((c) => c.number === '8');
  assert.equal(ch8.sections.length, 9, 'Chapter 8 must contain all 9 deployment principles');
});

test('SAA data - section IDs are unique and every section has readable content', () => {
  const ids = saa.SAA_ALL_SECTIONS.map((s) => s.id);
  assert.equal(new Set(ids).size, ids.length, 'Duplicate section IDs found');
  for (const s of saa.SAA_ALL_SECTIONS) {
    assert.match(s.id, /^SAA-[\dA](\.[\d]+)*(-[a-z]+)?$|^SAA-8\.\d$/, `Bad section id ${s.id}`);
    assert.ok(s.summary.length >= 20, `${s.id} summary too short`);
    assert.ok(s.blocks.length > 0, `${s.id} has no content blocks`);
    assert.ok((saa.SAA_SECTION_SEARCH_TEXT[s.id] ?? '').length > 80, `${s.id} search text too short`);
  }
});

// ─── 2. Domain model integrity ───────────────────────────────────────────────

test('SAA data - 6 key components, 15 T-code threats, all component threats resolvable', () => {
  assert.deepEqual(saa.SAA_KEY_COMPONENTS.map((k) => k.id), ['KC1', 'KC2', 'KC3', 'KC4', 'KC5', 'KC6']);
  assert.deepEqual(saa.SAA_THREATS.map((t) => t.id), Array.from({ length: 15 }, (_, i) => `T${i + 1}`));
  const threatIds = new Set(saa.SAA_THREATS.map((t) => t.id));
  for (const kc of saa.SAA_KEY_COMPONENTS) {
    assert.ok(kc.subcomponents.length >= 3, `${kc.id} sub-components`);
    assert.ok(kc.breaker.detect && kc.breaker.actions, `${kc.id} circuit breaker matrix row`);
    for (const t of kc.threats) assert.ok(threatIds.has(t.id), `${kc.id} references unknown ${t.id}`);
  }
  // Summary table (2.2) membership for KC6
  assert.deepEqual(saa.SAA_KEY_COMPONENTS[5].threats.map((t) => t.id), ['T2', 'T3', 'T4', 'T10', 'T11', 'T12', 'T13', 'T15']);
  for (const s of saa.SAA_ALL_SECTIONS) for (const t of s.threats ?? []) assert.ok(threatIds.has(t), `${s.id} references unknown ${t}`);
});

test('SAA data - related ASI cross-links point at real OWASP Agentic Top 10 entries', () => {
  const asi = read('src/data/data_agentic_applications.ts');
  for (const t of saa.SAA_THREATS) {
    if (t.relatedAsi) {
      assert.match(t.relatedAsi, /^ASI(0[1-9]|10)$/);
      assert.ok(asi.includes(`id: '${t.relatedAsi}'`), `${t.relatedAsi} must exist in data_agentic_applications.ts`);
    }
  }
});

test('SAA data - 18 hook points with valid scopes and five dispositions', () => {
  assert.equal(saa.SAA_HOOKS.length, 18);
  assert.deepEqual(saa.SAA_HOOK_DISPOSITIONS.map((d) => d.id), ['Allow', 'Deny', 'Modify', 'Escalate', 'Defer']);
  const allowed = new Set(['Allow', 'Deny', 'Modify', 'Escalate', 'Defer', 'Audit only', 'Audit + Modify']);
  for (const h of saa.SAA_HOOKS) {
    assert.ok(['Session', 'Turn', 'Inner'].includes(h.scope), `${h.id} scope`);
    for (const d of h.dispositions) assert.ok(allowed.has(d), `${h.id} has unknown disposition ${d}`);
  }
  const first = saa.SAA_HOOKS.filter((h) => h.priority === 'first').map((h) => h.id).sort();
  assert.deepEqual(first, ['agentResponse', 'toolCallRequest'], 'Guide says wire toolCallRequest and agentResponse first');
  assert.equal(saa.SAA_HOOKS.find((h) => h.priority === 'next')?.id, 'memoryStore');
  assert.equal(saa.SAA_HOOKS.find((h) => h.id === 'toolCallRequest').dispositions.length, 5);
});

test('SAA data - capability matrix covers KC6.1–KC6.6 and links to existing sections', () => {
  const ids = new Set(saa.SAA_ALL_SECTIONS.map((s) => s.id));
  assert.deepEqual(saa.SAA_CAPABILITIES.map((c) => c.kc), ['KC6.1', 'KC6.2', 'KC6.3', 'KC6.4', 'KC6.5', 'KC6.6']);
  for (const c of saa.SAA_CAPABILITIES) {
    assert.ok(ids.has(c.sectionId), `${c.id} links to missing ${c.sectionId}`);
    assert.ok(c.requiredControls.length > 20 && c.escalationTrigger.length > 5);
  }
  // Database/RAG has bounded egress: on its own it is two legs, not a trifecta.
  const db = saa.SAA_CAPABILITIES.find((c) => c.kc === 'KC6.3');
  assert.equal(db.legs.external, false);
});

test('SAA data - memory matrix is a complete 2 × 3 grid (KC4.1–KC4.6)', () => {
  assert.equal(saa.SAA_MEMORY_SCOPES.length, 6);
  const cells = new Set(saa.SAA_MEMORY_SCOPES.map((m) => `${m.sharing}|${m.persistence}`));
  assert.equal(cells.size, 6, 'Each sharing × persistence cell must appear exactly once');
  assert.deepEqual(saa.SAA_MEMORY_SCOPES.map((m) => m.id).sort(), ['KC4.1', 'KC4.2', 'KC4.3', 'KC4.4', 'KC4.5', 'KC4.6']);
});

test('SAA data - corrected architecture table maps web access to KC6.4 and RAG to KC6.3', () => {
  const reactive = saa.SAA_ARCHITECTURE_PATTERNS.find((p) => p.id === 'reactive');
  const knowledge = saa.SAA_ARCHITECTURE_PATTERNS.find((p) => p.id === 'knowledge');
  assert.match(reactive.comprehensive.environment, /KC6\.4/);
  assert.match(knowledge.comprehensive.environment, /KC6\.3/);
  assert.equal(saa.SAA_ARCHITECTURE_PATTERNS.length, 5);
  assert.equal(saa.SAA_ASSURANCE_CHAIN.length, 7);
  assert.ok(saa.SAA_EDITORIAL_NOTES.length >= 5, 'Corrections to the source must be documented');
});

test('SAA data - metadata cites the official publication and CC BY-SA 4.0', () => {
  const m = saa.SECURING_AGENTIC_APPS_META;
  assert.equal(m.sourceUrl, 'https://genai.owasp.org/resource/securing-agentic-applications-v2/');
  assert.equal(m.version, '2.0');
  assert.equal(m.publicationDate, 'October 2026');
  assert.match(m.license.name, /CC BY-SA 4\.0/);
  for (const s of saa.SAA_ALL_SECTIONS) {
    for (const b of s.blocks) {
      if (b.type === 'links') for (const l of b.items) assert.match(l.url, /^https:\/\//, `${s.id} link must be https`);
    }
  }
});

// ─── 3. Widget wiring ────────────────────────────────────────────────────────

test('SAA view - every widget referenced in data is implemented and used exactly once', () => {
  const widgetsSrc = read('src/components/securing-agentic/SaaWidgets.tsx');
  const used = saa.SAA_ALL_SECTIONS.flatMap((s) => s.blocks.filter((b) => b.type === 'widget').map((b) => b.widget));
  assert.equal(new Set(used).size, used.length, 'A widget is embedded twice');
  assert.equal(used.length, 15, 'Expected 15 interactive labs');
  for (const w of used) {
    assert.ok(widgetsSrc.includes(`case '${w}':`), `Widget ${w} is not handled by SaaWidget`);
    assert.ok(widgetsSrc.includes(`'${w}': '`), `Widget ${w} needs a label`);
  }
});

test('SAA view - accessible tabs, search, deep links, and safe external links', () => {
  const view = read('src/components/SecuringAgenticAppsView.tsx');
  assert.ok(view.includes('role="tablist"') && view.includes('role="tab"') && view.includes('role="tabpanel"'), 'Chapter tabs must use the ARIA tab pattern');
  assert.ok(view.includes('aria-expanded') && view.includes('aria-controls'), 'Sections must be accessible disclosures');
  assert.ok(view.includes('#/securing-agentic-apps/'), 'Sections must expose deep links');
  assert.ok(view.includes('content-auto'), 'Long section list must use content-visibility');
  assert.ok(!/dangerouslySetInnerHTML|\.innerHTML/.test(view), 'No raw HTML injection');
  const anchors = [...view.matchAll(/<a\s[^>]*target="_blank"[^>]*>/g)].map((m) => m[0]);
  assert.ok(anchors.length >= 3);
  for (const a of anchors) assert.ok(a.includes('rel="noopener noreferrer"'), `Unsafe anchor: ${a}`);
});

// ─── 4. Read-progress storage hardening (executed) ───────────────────────────

test('SAA progress - sanitizer whitelists known IDs and rejects poisoning payloads', () => {
  const valid = new Set(saa.SAA_ALL_SECTIONS.map((s) => s.id));
  const { sanitizeReadProgress } = progress;
  assert.deepEqual(sanitizeReadProgress({ __proto__: { polluted: true } }, valid), []);
  assert.deepEqual(sanitizeReadProgress('SAA-1.1', valid), []);
  const out = sanitizeReadProgress(['SAA-1.1', 'SAA-1.1', '__proto__', 'constructor', '<img src=x>', 42, null, 'SAA-3.3.7', 'x'.repeat(5000)], valid);
  assert.deepEqual(out, ['SAA-1.1', 'SAA-3.3.7']);
  assert.equal({}.polluted, undefined, 'Object prototype must stay clean');
  assert.equal(sanitizeReadProgress(Array(10000).fill('SAA-1.1'), valid).length, 1);
  assert.match(progress.SAA_PROGRESS_STORAGE_KEY, /^ai-nexus-/);
});

// ─── 5. App integration ──────────────────────────────────────────────────────

test('SAA integration - routing, sidebar, dashboard, global search, and barrel', () => {
  const app = read('src/App.tsx');
  assert.ok(app.includes("lazy(() => import('./components/SecuringAgenticAppsView'))"), 'View must be lazy-loaded');
  assert.ok(app.includes("clean === 'securing-agentic-apps'") && app.includes("upper.startsWith('SAA-')"), 'Hash parser must route the guide');
  assert.ok(app.includes("if (view === 'securing-agentic-apps') return"), 'stateToHash must serialize the guide view');
  assert.ok(app.includes("if (view === 'red-teaming-manual') return"), 'stateToHash must serialize the red teaming view');
  assert.ok(app.includes('id.startsWith("SAA-")'), 'handleNavigateToOwasp must route SAA-* ids');

  const sidebar = read('src/components/Sidebar.tsx');
  assert.ok(sidebar.includes("| 'securing-agentic-apps'") && sidebar.includes("'SECUREAGENTICAPPS'"));

  const dash = read('src/components/Dashboard.tsx');
  assert.ok(dash.includes("key: 'SECUREAGENTICAPPS'"), 'Dashboard must show a framework card');

  const search = read('src/components/GlobalSearchModal.tsx');
  assert.ok(search.includes("category: 'saa'") && search.includes('SAA_ALL_SECTIONS') && search.includes('SAA_HOOKS'), 'Global search must index the guide');

  assert.ok(read('src/data/data.ts').includes("export * from './data_securing_agentic_apps'"));
  assert.ok(read('vite.config.ts').includes('data_securing_agentic_apps'), 'Data must be assigned to a manual chunk');
});
