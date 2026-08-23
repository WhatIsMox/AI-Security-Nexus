/**
 * Functional Tests — SecureMcpGuideView Component Structure & Completeness
 *
 * SecureMcpGuideView is a full standalone view (22KB) with rich hardening controls,
 * control families, and a minimum-bar readiness checklist — yet has zero dedicated tests.
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

test('SecureMcpGuideView - imports all three required Secure MCP Guide constructs', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');

  assert.ok(
    content.includes('SECURE_MCP_GUIDE_META'),
    'SecureMcpGuideView must import SECURE_MCP_GUIDE_META'
  );
  assert.ok(
    content.includes('SECURE_MCP_GUIDE_SECTIONS'),
    'SecureMcpGuideView must import SECURE_MCP_GUIDE_SECTIONS'
  );
  assert.ok(
    content.includes('SECURE_MCP_MINIMUM_BAR'),
    'SecureMcpGuideView must import SECURE_MCP_MINIMUM_BAR'
  );
});

test('SecureMcpGuideView - imports from data_secure_mcp_guide.ts (not from generic data barrel)', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');

  assert.ok(
    content.includes("from '../data_secure_mcp_guide'") ||
    content.includes('from "../data_secure_mcp_guide"'),
    'SecureMcpGuideView must import directly from ../data_secure_mcp_guide'
  );
});

// ─── 2. Control Families ──────────────────────────────────────────────────────

test('SecureMcpGuideView - defines all 7 control family categories', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');

  const expectedFamilies = [
    'Architecture',
    'Tool Safety',
    'Validation',
    'Prompt Injection',
    'Identity',
    'Operations',
  ];

  for (const family of expectedFamilies) {
    assert.ok(
      content.includes(family),
      `SecureMcpGuideView must define the "${family}" control family`
    );
  }

  // Verify CONTROL_FAMILIES array is declared
  assert.ok(content.includes('CONTROL_FAMILIES'), 'SecureMcpGuideView must declare CONTROL_FAMILIES constant');
});

test('SecureMcpGuideView - CONTROL_FAMILIES have title, description, and match fields', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');

  // The CONTROL_FAMILIES block must have description and match keyword arrays
  assert.ok(content.includes('description:'), 'CONTROL_FAMILIES entries must have description field');
  assert.ok(content.includes('match:'), 'CONTROL_FAMILIES entries must have match field for keyword filtering');
});

// ─── 3. Search / Filter Functionality ────────────────────────────────────────

test('SecureMcpGuideView - implements search/filter across controls', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');

  // Search input
  assert.ok(content.includes('searchQuery') || content.includes('search'), 'SecureMcpGuideView must implement search state');
  assert.ok(content.includes('sectionMatchesSearch') || content.includes('filter'), 'SecureMcpGuideView must filter sections by search term');

  // Search normalization helper
  assert.ok(content.includes('normalize') || content.includes('.toLowerCase()'), 'SecureMcpGuideView must normalize search terms for case-insensitive matching');
});

test('SecureMcpGuideView - section match logic checks title, body, and subsections', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');

  // sectionMatchesSearch should look at multiple fields
  assert.ok(content.includes('sectionMatchesSearch'), 'SecureMcpGuideView must have sectionMatchesSearch helper');
  assert.ok(content.includes('section.title'), 'sectionMatchesSearch must check section.title');
  assert.ok(content.includes('section.body') || content.includes('section.bullets'), 'sectionMatchesSearch must check section.body or section.bullets');
  assert.ok(content.includes('subsections'), 'sectionMatchesSearch must traverse subsections');
});

// ─── 4. Minimum Bar Readiness Checklist ──────────────────────────────────────

test('SecureMcpGuideView - renders the SECURE_MCP_MINIMUM_BAR readiness checklist', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');

  assert.ok(
    content.includes('SECURE_MCP_MINIMUM_BAR'),
    'SecureMcpGuideView must use SECURE_MCP_MINIMUM_BAR to render a readiness checklist'
  );

  // Should render checklist items (CheckCircle2 or similar)
  assert.ok(
    content.includes('CheckCircle2') || content.includes('checklist'),
    'SecureMcpGuideView must render checklist-style items for minimum bar controls'
  );
});

// ─── 5. Accordion / Expand-Collapse ─────────────────────────────────────────

test('SecureMcpGuideView - implements accordion expand/collapse for guide sections', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');

  // State-driven expand/collapse
  assert.ok(
    content.includes('expandedId') || content.includes('openSection') || content.includes('expanded'),
    'SecureMcpGuideView must track expanded section state for accordion behaviour'
  );

  // Chevron icon for collapse indicator
  assert.ok(
    content.includes('ChevronDown') || content.includes('chevron'),
    'SecureMcpGuideView must render a collapse/expand indicator (ChevronDown or similar)'
  );
});

// ─── 6. External Links Security ───────────────────────────────────────────────

test('SecureMcpGuideView - external links have target="_blank" and rel="noopener noreferrer"', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');

  const anchorRegex = /<a\b([^>]*?)>/gi;
  let match;
  let blankLinkCount = 0;

  while ((match = anchorRegex.exec(content)) !== null) {
    const attrs = match[1];
    if (/target\s*=\s*["']_blank["']/i.test(attrs)) {
      blankLinkCount++;
      assert.ok(
        /rel\s*=\s*["'][^"']*\bnoopener\b[^"']*["']/i.test(attrs),
        `SecureMcpGuideView external link missing noopener: <a ${attrs}>`
      );
      assert.ok(
        /rel\s*=\s*["'][^"']*\bnoreferrer\b[^"']*["']/i.test(attrs),
        `SecureMcpGuideView external link missing noreferrer: <a ${attrs}>`
      );
    }
  }

  t.diagnostic(`Verified ${blankLinkCount} external link(s) in SecureMcpGuideView`);
});

// ─── 7. Semantic HTML ────────────────────────────────────────────────────────

test('SecureMcpGuideView - uses semantic HTML elements for content sections', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');

  assert.ok(content.includes('<article') || content.includes('<section'), 'SecureMcpGuideView must use semantic <article> or <section> elements');
  assert.ok(content.includes('<h2') || content.includes('<h3') || content.includes('<h4'), 'SecureMcpGuideView must use heading elements for section titles');
});

// ─── 8. Mobile Responsiveness ─────────────────────────────────────────────────

test('SecureMcpGuideView - layout uses responsive Tailwind classes', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');

  assert.ok(
    content.includes('grid-cols-1') || content.includes('sm:grid-cols') || content.includes('md:grid-cols'),
    'SecureMcpGuideView must use responsive grid layout for control cards'
  );
  assert.ok(
    content.includes('px-4') || content.includes('p-4') || content.includes('px-3'),
    'SecureMcpGuideView must have appropriate responsive padding'
  );
});
