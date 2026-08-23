/**
 * Functional Tests — AgenticTop10View Dual-Tab Architecture
 *
 * AgenticTop10View is unique: it hosts TWO distinct OWASP frameworks (ASI and AST)
 * in a single view, with a tab switcher and auto-routing logic. This is entirely
 * untested despite being one of the most complex components in the app.
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
  return fs.readFileSync(path.join(rootDir, relativePath), 'utf8');
}

// ─── 1. Data Source Imports ───────────────────────────────────────────────────

test('AgenticTop10View - imports both ASI and AST data from barrel', (t) => {
  const content = readFile('components/AgenticTop10View.tsx');

  assert.ok(
    content.includes('OWASP_AGENTIC_APPLICATIONS_DATA'),
    'AgenticTop10View must import OWASP_AGENTIC_APPLICATIONS_DATA (ASI)'
  );
  assert.ok(
    content.includes('OWASP_AGENTIC_THREATS_DATA'),
    'AgenticTop10View must import OWASP_AGENTIC_THREATS_DATA (AST)'
  );
  assert.ok(
    content.includes('AGENTIC_APPLICATIONS_OVERVIEW'),
    'AgenticTop10View must import AGENTIC_APPLICATIONS_OVERVIEW'
  );
  assert.ok(
    content.includes('AGENTIC_SKILLS_OVERVIEW'),
    'AgenticTop10View must import AGENTIC_SKILLS_OVERVIEW'
  );
});

test('AgenticTop10View - delegates rendering to OwaspTop10View for both tabs', (t) => {
  const content = readFile('components/AgenticTop10View.tsx');

  assert.ok(
    content.includes("import OwaspTop10View") || content.includes("from './OwaspTop10View'"),
    'AgenticTop10View must import OwaspTop10View for content delegation'
  );
  assert.ok(content.includes('<OwaspTop10View'), 'AgenticTop10View must render OwaspTop10View components');

  // Must pass relevant data to both panel instances
  assert.ok(
    content.includes('OWASP_AGENTIC_APPLICATIONS_DATA') && content.includes('data={OWASP_AGENTIC_APPLICATIONS_DATA}'),
    'Must pass OWASP_AGENTIC_APPLICATIONS_DATA to ASI OwaspTop10View panel'
  );
  assert.ok(
    content.includes('OWASP_AGENTIC_THREATS_DATA') && content.includes('data={OWASP_AGENTIC_THREATS_DATA}'),
    'Must pass OWASP_AGENTIC_THREATS_DATA to AST OwaspTop10View panel'
  );
});

// ─── 2. ARIA Tab Pattern ──────────────────────────────────────────────────────

test('AgenticTop10View - uses ARIA tab pattern for ASI/AST framework switcher', (t) => {
  const content = readFile('components/AgenticTop10View.tsx');

  // ARIA role attributes
  assert.ok(content.includes('role="tablist"'), 'AgenticTop10View must use role="tablist" on the tab group');
  assert.ok(content.includes('role="tab"'), 'AgenticTop10View must use role="tab" on each tab button');
  assert.ok(content.includes('role="tabpanel"'), 'AgenticTop10View must use role="tabpanel" on each content panel');

  // ARIA linking attributes
  assert.ok(content.includes('aria-selected'), 'AgenticTop10View tabs must use aria-selected');
  assert.ok(content.includes('aria-controls'), 'AgenticTop10View tabs must use aria-controls to link to panels');
  assert.ok(content.includes('aria-labelledby'), 'AgenticTop10View panels must use aria-labelledby to link back to tabs');
});

test('AgenticTop10View - tab buttons have unique stable IDs', (t) => {
  const content = readFile('components/AgenticTop10View.tsx');

  // Specific IDs for Applications and Skills tabs
  assert.ok(
    content.includes('agentic-applications-tab') || content.includes('id="agentic-applications'),
    'ASI tab button must have a stable HTML id'
  );
  assert.ok(
    content.includes('agentic-skills-tab') || content.includes('id="agentic-skills'),
    'AST tab button must have a stable HTML id'
  );

  // Panel IDs to complete the ARIA linkage
  assert.ok(
    content.includes('agentic-applications-panel') || content.includes('id="agentic-applications-panel'),
    'ASI tab panel must have a stable HTML id'
  );
  assert.ok(
    content.includes('agentic-skills-panel') || content.includes('id="agentic-skills-panel'),
    'AST tab panel must have a stable HTML id'
  );
});

// ─── 3. Auto-Routing via initialExpandedId ────────────────────────────────────

test('AgenticTop10View - auto-selects AST tab when initialExpandedId starts with AST', (t) => {
  const content = readFile('components/AgenticTop10View.tsx');

  // Logic that initializes framework state based on initialExpandedId prefix
  assert.ok(
    content.includes("startsWith('AST')") || content.includes('startsWith("AST")'),
    'AgenticTop10View must detect AST prefix in initialExpandedId to auto-select Skills tab'
  );
  assert.ok(
    content.includes("startsWith('ASI')") || content.includes('startsWith("ASI")'),
    'AgenticTop10View must detect ASI prefix in initialExpandedId to auto-select Applications tab'
  );

  // Must use useEffect to respond to prop changes
  assert.ok(content.includes('useEffect'), 'AgenticTop10View must use useEffect to respond to initialExpandedId changes');
});

test('AgenticTop10View - passes correct initialExpandedId subset to each OwaspTop10View panel', (t) => {
  const content = readFile('components/AgenticTop10View.tsx');

  // ASI panel: only forward the id when it starts with ASI
  assert.ok(
    content.includes("startsWith('ASI') ? initialExpandedId : null") ||
    content.includes('startsWith("ASI") ? initialExpandedId : null'),
    'ASI panel must only receive initialExpandedId when the ID starts with ASI'
  );

  // AST panel: only forward the id when it starts with AST
  assert.ok(
    content.includes("startsWith('AST') ? initialExpandedId : null") ||
    content.includes('startsWith("AST") ? initialExpandedId : null'),
    'AST panel must only receive initialExpandedId when the ID starts with AST'
  );
});

// ─── 4. Framework Metadata & Color Theming ────────────────────────────────────

test('AgenticTop10View - applies distinct color themes for ASI (orange) and AST (cyan)', (t) => {
  const content = readFile('components/AgenticTop10View.tsx');

  // Applications tab = orange theme (ASI)
  assert.ok(content.includes('orange'), 'AgenticTop10View must apply orange color theme for Applications (ASI) tab');
  // Skills tab = cyan theme (AST)
  assert.ok(content.includes('cyan'), 'AgenticTop10View must apply cyan color theme for Skills (AST) tab');

  // colorTheme prop is passed to OwaspTop10View
  assert.ok(
    content.includes('colorTheme="orange"') || content.includes("colorTheme='orange'"),
    'Must pass colorTheme="orange" to ASI OwaspTop10View'
  );
  assert.ok(
    content.includes('colorTheme="cyan"') || content.includes("colorTheme='cyan'"),
    'Must pass colorTheme="cyan" to AST OwaspTop10View'
  );
});

test('AgenticTop10View - renders correct framework descriptions for each tab', (t) => {
  const content = readFile('components/AgenticTop10View.tsx');

  // ASI description must mention agentic applications context
  assert.ok(
    content.includes('Agentic Applications') || content.includes('agentic application'),
    'AgenticTop10View must render a description for the ASI (Agentic Applications) framework'
  );

  // AST description must mention skills/tools context
  assert.ok(
    content.includes('Agentic Skills') || content.includes('agentic skill'),
    'AgenticTop10View must render a description for the AST (Agentic Skills) framework'
  );
});

// ─── 5. External Source Links Security ───────────────────────────────────────

test('AgenticTop10View - external source links have target="_blank" and rel="noopener noreferrer"', (t) => {
  const content = readFile('components/AgenticTop10View.tsx');

  const anchorRegex = /<a\b([^>]*?)>/gi;
  let match;
  let checkedCount = 0;

  while ((match = anchorRegex.exec(content)) !== null) {
    const attrs = match[1];
    if (/target\s*=\s*["']_blank["']/i.test(attrs)) {
      checkedCount++;
      assert.ok(
        /rel\s*=\s*["'][^"']*\bnoopener\b[^"']*["']/i.test(attrs),
        `External link in AgenticTop10View missing rel="noopener noreferrer": <a ${attrs}>`
      );
      assert.ok(
        /rel\s*=\s*["'][^"']*\bnoreferrer\b[^"']*["']/i.test(attrs),
        `External link in AgenticTop10View missing rel="noopener noreferrer": <a ${attrs}>`
      );
    }
  }

  assert.ok(checkedCount > 0, 'AgenticTop10View must contain at least one external link with target="_blank"');
  t.diagnostic(`Verified ${checkedCount} external link(s) in AgenticTop10View`);
});

// ─── 6. Official Source URLs ──────────────────────────────────────────────────

test('AgenticTop10View - references official OWASP source URLs for both frameworks', (t) => {
  const content = readFile('components/AgenticTop10View.tsx');

  assert.ok(
    content.includes('genai.owasp.org') || content.includes('owasp.org'),
    'AgenticTop10View must reference an official OWASP source URL for the ASI framework'
  );
  assert.ok(
    content.includes('owasp.org/www-project-agentic-skills') || content.includes('owasp.org'),
    'AgenticTop10View must reference an official OWASP source URL for the AST framework'
  );
});
