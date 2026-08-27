/**
 * Functional Tests — In-Page Navigation & Hash Routing Resilience
 *
 * Verifies that in-page navigation (Navigator TOC, Risk Index, Control Families)
 * in GenAiDataSecurityView and SecureMcpGuideView uses dedicated smooth-scrolling
 * button handlers and does not overwrite or corrupt SPA routing hashes,
 * and ensures App.tsx parseHashToState resolves deep links and threat IDs reliably.
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

// ─── 1. GenAiDataSecurityView In-Page Navigation ──────────────────────────────

test('GenAiDataSecurityView - Navigator uses button elements with scrollToSection without hash clobbering', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  assert.ok(
    content.includes('scrollToSection'),
    'GenAiDataSecurityView must define a scrollToSection smooth scrolling handler'
  );

  // Assert no raw href="#..." anchor tags inside TOC Navigator
  assert.ok(
    !content.includes('href={`#${item.targetId}`}'),
    'GenAiDataSecurityView TOC must not use raw href="#${item.targetId}" anchors'
  );
  assert.ok(
    !content.includes('href={`#${risk.id}`}'),
    'GenAiDataSecurityView Risk Index must not use raw href="#${risk.id}" anchors'
  );
});

test('GenAiDataSecurityView - supports initialExpandedId prop and auto-scrolls', (t) => {
  const content = readFile('components/GenAiDataSecurityView.tsx');

  assert.ok(
    content.includes('initialExpandedId'),
    'GenAiDataSecurityView must support initialExpandedId prop'
  );
  assert.ok(
    content.includes('scrollToSection(initialExpandedId)') ||
    content.includes('scrollToRisk(initialExpandedId)'),
    'GenAiDataSecurityView must scroll to initialExpandedId when mounted'
  );
});

// ─── 2. SecureMcpGuideView In-Page Navigation ────────────────────────────────

test('SecureMcpGuideView - Control Families and Navigator use button elements with scrollToSection', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');

  assert.ok(
    content.includes('scrollToSection'),
    'SecureMcpGuideView must define a scrollToSection smooth scrolling handler'
  );

  // Assert no raw href="#..." anchor tags inside Control Families or Navigator
  assert.ok(
    !content.includes('href={`#${section.id}`}'),
    'SecureMcpGuideView Navigator must not use raw href="#${section.id}" anchors'
  );
  assert.ok(
    !content.includes('href="#minimum-bar"'),
    'SecureMcpGuideView Minimum Bar link must not use raw href="#minimum-bar" anchor'
  );
});

test('SecureMcpGuideView - supports initialExpandedId prop and auto-expands target section', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');

  assert.ok(
    content.includes('initialExpandedId'),
    'SecureMcpGuideView must accept initialExpandedId in props'
  );
  assert.ok(
    content.includes('setExpandedSections'),
    'SecureMcpGuideView must dynamically expand sections on interaction or mount'
  );
});

// ─── 3. App.tsx Hash Routing Resilience ──────────────────────────────────────

test('App.tsx - parseHashToState resolves deep links and threat IDs reliably', (t) => {
  const content = readFile('App.tsx');

  assert.ok(
    content.includes("clean.startsWith('secure-mcp-guide')") || content.includes("clean.startsWith('secure-mcp-guide/')"),
    'App.tsx parseHashToState must handle secure-mcp-guide deep links'
  );
  assert.ok(
    content.includes("clean.startsWith('DSGAI')") || content.includes("clean === 'minimum-bar'"),
    'App.tsx parseHashToState must handle direct section and risk IDs without resetting to dashboard'
  );
  assert.ok(
    content.includes("clean.startsWith('LLM')") &&
    content.includes("clean.startsWith('ML')") &&
    content.includes("clean.startsWith('MCP')"),
    'App.tsx parseHashToState must recognize framework threat prefix IDs'
  );
});

test('App.tsx - passes initialExpandedId to SecureMcpGuideView and GenAiDataSecurityView', (t) => {
  const content = readFile('App.tsx');

  assert.ok(
    content.includes('<SecureMcpGuideView initialExpandedId={owaspTargetId} />'),
    'App.tsx must pass initialExpandedId to SecureMcpGuideView'
  );
  assert.ok(
    content.includes('<GenAiDataSecurityView initialExpandedId={owaspTargetId} />'),
    'App.tsx must pass initialExpandedId to GenAiDataSecurityView'
  );
});
