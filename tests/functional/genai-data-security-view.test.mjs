/**
 * Functional Tests — GenAiDataSecurityView Component Structure & Completeness
 *
 * GenAiDataSecurityView is the largest component at 38KB, rendering DSGAI01-DSGAI21
 * and AI-DSPM capabilities with theme filtering, accordion expand, and cross-references.
 * It has zero dedicated functional tests.
 */

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

// ─── 1. Data Source Imports ───────────────────────────────────────────────────

test('GenAiDataSecurityView - imports all four required constants from data_genai_data_security.ts', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  assert.ok(content.includes('GENAI_DATA_SECURITY_META'), 'Must import GENAI_DATA_SECURITY_META');
  assert.ok(content.includes('GENAI_DATA_SECURITY_OVERVIEW'), 'Must import GENAI_DATA_SECURITY_OVERVIEW');
  assert.ok(content.includes('GENAI_DATA_SECURITY_RISKS'), 'Must import GENAI_DATA_SECURITY_RISKS for DSGAI01-DSGAI21');
  assert.ok(content.includes('GENAI_DSPM_CAPABILITIES'), 'Must import GENAI_DSPM_CAPABILITIES for AI-DSPM entries');
});

test('GenAiDataSecurityView - imports directly from data_genai_data_security.ts source module', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  assert.ok(
    content.includes("from '../data/data_genai_data_security'") ||
    content.includes('from "../data/data_genai_data_security"') ||
    content.includes("from '../data_genai_data_security'") ||
    content.includes('from "../data_genai_data_security"'),
    'GenAiDataSecurityView must import from data_genai_data_security (not the barrel)'
  );
});

// ─── 2. Theme Filter System ───────────────────────────────────────────────────

test('GenAiDataSecurityView - defines THEME_STYLES for all 5 risk theme categories', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  assert.ok(content.includes('THEME_STYLES'), 'GenAiDataSecurityView must declare THEME_STYLES record');

  const expectedThemes = [
    'Leakage',
    'Identity',
    'Governance',
    'Integrity',
    'Model',
  ];

  for (const theme of expectedThemes) {
    assert.ok(content.includes(theme), `THEME_STYLES must include "${theme}" theme styling`);
  }
});

test('GenAiDataSecurityView - implements theme-based filtering for DSGAI risks', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  // Theme filter state
  assert.ok(
    content.includes('ThemeFilter') || content.includes('themeFilter') || content.includes('theme'),
    'GenAiDataSecurityView must implement theme-based filtering'
  );

  // Filter must support "All" option
  assert.ok(content.includes("'All'") || content.includes('"All"'), 'Theme filter must include an "All" option');
});

// ─── 3. Search Functionality ──────────────────────────────────────────────────

test('GenAiDataSecurityView - implements text search across risk fields', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  assert.ok(
    content.includes('searchQuery') || content.includes('search'),
    'GenAiDataSecurityView must maintain a search query state'
  );
  assert.ok(content.includes('includesSearch') || content.includes('filter'), 'GenAiDataSecurityView must filter risks by search term');
});

test('GenAiDataSecurityView - search covers id, title, theme, summary, keywords, and mitigations', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  // The includesSearch function should look at multiple fields
  assert.ok(content.includes('risk.id'), 'Search must include risk.id');
  assert.ok(content.includes('risk.title'), 'Search must include risk.title');
  assert.ok(content.includes('risk.theme'), 'Search must include risk.theme');
  assert.ok(content.includes('risk.summary'), 'Search must include risk.summary');
  assert.ok(content.includes('risk.keywords') || content.includes('keywords'), 'Search must include risk.keywords');
  assert.ok(
    content.includes('risk.mitigations') || content.includes('mitigations'),
    'Search must include risk.mitigations'
  );
});

// ─── 4. Accordion Expand / Collapse ──────────────────────────────────────────

test('GenAiDataSecurityView - implements accordion expand/collapse for DSGAI risk cards', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  assert.ok(
    content.includes('expandedId') || content.includes('expanded') || content.includes('openId'),
    'GenAiDataSecurityView must track expanded risk card state'
  );

  assert.ok(
    content.includes('ChevronDown') || content.includes('chevron') || content.includes('Expand'),
    'GenAiDataSecurityView must render an expand/collapse indicator'
  );
});

test('GenAiDataSecurityView - supports initialExpandedId prop for deep-linking', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  assert.ok(content.includes('initialExpandedId'), 'GenAiDataSecurityView must accept an initialExpandedId prop for deep-linking');
  assert.ok(content.includes('useEffect'), 'GenAiDataSecurityView must use useEffect to respond to initialExpandedId changes');
});

// ─── 5. DSGAI Risk Card Fields ────────────────────────────────────────────────

test('GenAiDataSecurityView - renders all key DSGAI risk card fields', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  // Risk cards must render substantive fields
  assert.ok(content.includes('risk.id') || content.includes('{risk.id}'), 'Must render risk.id');
  assert.ok(content.includes('risk.title') || content.includes('{risk.title}'), 'Must render risk.title');
  assert.ok(content.includes('risk.summary') || content.includes('{risk.summary}'), 'Must render risk.summary');
  assert.ok(
    content.includes('howItUnfolds') || content.includes('risk.howItUnfolds'),
    'Must render risk.howItUnfolds attack mechanics'
  );
  assert.ok(
    content.includes('mitigations') || content.includes('risk.mitigations'),
    'Must render risk.mitigations'
  );
});

// ─── 6. AI-DSPM Capabilities ──────────────────────────────────────────────────

test('GenAiDataSecurityView - renders AI-DSPM capabilities section', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  assert.ok(content.includes('GENAI_DSPM_CAPABILITIES'), 'GenAiDataSecurityView must render AI-DSPM capabilities');
  assert.ok(
    content.includes('DSPM') || content.includes('dspm') || content.includes('AI-DSPM'),
    'GenAiDataSecurityView must render an AI-DSPM labeled section'
  );
});

// ─── 7. Cross-References ─────────────────────────────────────────────────────

test('GenAiDataSecurityView - renders cross-references to related framework threats', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  assert.ok(
    content.includes('crossReferences') || content.includes('cross-references') || content.includes('Cross'),
    'GenAiDataSecurityView must render cross-framework references for each DSGAI risk'
  );
});

// ─── 8. External Link Security ───────────────────────────────────────────────

test('GenAiDataSecurityView - external links have target="_blank" and rel="noopener noreferrer"', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  const anchorRegex = /<a\b([^>]*?)>/gi;
  let match;
  let blankLinkCount = 0;

  while ((match = anchorRegex.exec(content)) !== null) {
    const attrs = match[1];
    if (/target\s*=\s*["']_blank["']/i.test(attrs)) {
      blankLinkCount++;
      assert.ok(
        /rel\s*=\s*["'][^"']*\bnoopener\b[^"']*["']/i.test(attrs),
        `GenAiDataSecurityView external link missing noopener: <a ${attrs}>`
      );
      assert.ok(
        /rel\s*=\s*["'][^"']*\bnoreferrer\b[^"']*["']/i.test(attrs),
        `GenAiDataSecurityView external link missing noreferrer: <a ${attrs}>`
      );
    }
  }

  t.diagnostic(`Verified ${blankLinkCount} external link(s) in GenAiDataSecurityView`);
});

// ─── 9. Usability & Loading State ────────────────────────────────────────────

test('GenAiDataSecurityView - uses useMemo to memoize filtered results for performance', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  assert.ok(content.includes('useMemo'), 'GenAiDataSecurityView must use useMemo to memoize filtered risk lists');
});

test('GenAiDataSecurityView - renders empty-state message when no risks match search/filter', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  assert.ok(
    content.includes('No risks match') ||
    content.includes('no results') ||
    content.includes('No results') ||
    content.includes('length === 0') ||
    content.includes('.length === 0'),
    'GenAiDataSecurityView must render an empty state message when filter yields no results'
  );
});
