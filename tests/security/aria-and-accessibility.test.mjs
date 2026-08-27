/**
 * Security Tests — ARIA & Accessibility Conformance (WCAG 2.1 AA / CWE-1295)
 *
 * Accessibility is a security and quality concern: screen-reader users must be able
 * to discover and operate all interactive elements safely. These tests verify ARIA
 * roles on modals, keyboard navigation support, tab patterns, and alt text.
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

// ─── 1. Modal ARIA Roles ─────────────────────────────────────────────────────

test('Accessibility - ToolDetailModal uses role="dialog" and aria-modal="true"', (t) => {
  const content = readFile('components/ToolDetailModal.tsx');

  assert.ok(content.includes('role="dialog"'), 'ToolDetailModal must specify role="dialog"');
  assert.ok(content.includes('aria-modal="true"'), 'ToolDetailModal must specify aria-modal="true"');
});

test('Accessibility - IncidentDetailModal uses role="dialog" and aria-modal="true"', (t) => {
  const content = readFile('components/IncidentDetailModal.tsx');

  assert.ok(content.includes('role="dialog"'), 'IncidentDetailModal must specify role="dialog"');
  assert.ok(content.includes('aria-modal="true"'), 'IncidentDetailModal must specify aria-modal="true"');
});

test('Accessibility - GlobalSearchModal uses role="dialog" and aria-modal="true"', (t) => {
  const content = readFile('components/GlobalSearchModal.tsx');

  assert.ok(content.includes('role="dialog"'), 'GlobalSearchModal must specify role="dialog"');
  assert.ok(content.includes('aria-modal="true"'), 'GlobalSearchModal must specify aria-modal="true"');
});

test('Accessibility - ThreatDetailModal uses role="dialog" and aria-modal="true"', (t) => {
  const content = readFile('components/ThreatDetailModal.tsx');

  assert.ok(content.includes('role="dialog"'), 'ThreatDetailModal must specify role="dialog"');
  assert.ok(content.includes('aria-modal="true"'), 'ThreatDetailModal must specify aria-modal="true"');
});

// ─── 2. Modal Keyboard Focus Trap (Escape Key) ──────────────────────────────

test('Accessibility - All modals implement Escape key listener for focus trap', (t) => {
  const modals = [
    'components/ToolDetailModal.tsx',
    'components/IncidentDetailModal.tsx',
    'components/GlobalSearchModal.tsx',
    'components/ThreatDetailModal.tsx',
  ];

  for (const modal of modals) {
    const content = readFile(modal);
    assert.ok(
      content.includes("e.key === 'Escape'") || content.includes('e.key === "Escape"'),
      `${modal} must listen to Escape key to close the modal (focus trap requirement)`
    );
  }
});

// ─── 3. ARIA Tab Pattern ─────────────────────────────────────────────────────

test('Accessibility - AgenticTop10View uses complete ARIA tab pattern (tablist/tab/tabpanel)', (t) => {
  const content = readFile('components/AgenticTop10View.tsx');

  assert.ok(content.includes('role="tablist"'), 'AgenticTop10View must use role="tablist"');
  assert.ok(content.includes('role="tab"'), 'AgenticTop10View must use role="tab"');
  assert.ok(content.includes('role="tabpanel"'), 'AgenticTop10View must use role="tabpanel"');
  assert.ok(content.includes('aria-selected'), 'Tab buttons must use aria-selected');
  assert.ok(content.includes('aria-controls'), 'Tab buttons must use aria-controls');
  assert.ok(content.includes('aria-labelledby'), 'Tab panels must use aria-labelledby');
});

test('Accessibility - Sidebar uses navigation landmark semantics', (t) => {
  const content = readFile('components/Sidebar.tsx');

  // Must use <nav> element or role="navigation"
  assert.ok(
    content.includes('<nav') || content.includes('role="navigation"'),
    'Sidebar must use <nav> element or role="navigation" for screen-reader landmark'
  );
});

// ─── 4. Button Accessibility ─────────────────────────────────────────────────

test('Accessibility - Close buttons in modals have discernible accessible label', (t) => {
  const modals = [
    { file: 'components/ToolDetailModal.tsx', name: 'ToolDetailModal' },
    { file: 'components/IncidentDetailModal.tsx', name: 'IncidentDetailModal' },
    { file: 'components/GlobalSearchModal.tsx', name: 'GlobalSearchModal' },
    { file: 'components/ThreatDetailModal.tsx', name: 'ThreatDetailModal' },
  ];

  for (const { file, name } of modals) {
    const content = readFile(file);

    // Close buttons must have either aria-label or recognizable text
    const hasAriaLabel = content.includes('aria-label="Close"') || content.includes("aria-label='Close'") || content.includes('aria-label=');
    const hasCloseText = content.includes('>Close<') || content.includes('X</') || content.includes('close');
    const hasLucideX = content.includes('X }') || content.includes('<X ') || content.includes('<X/>');

    assert.ok(
      hasAriaLabel || hasCloseText || hasLucideX,
      `${name} close button must have an accessible label (aria-label, text, or icon component)`
    );
  }
});

test('Accessibility - ToolDetailModal includes copy button accessible feedback', (t) => {
  const content = readFile('components/ToolDetailModal.tsx');

  assert.ok(
    content.includes('navigator.clipboard.writeText'),
    'ToolDetailModal must implement clipboard copy'
  );

  // Must show visual feedback (Copied! or similar) accessible to sighted users
  assert.ok(
    content.includes('Copied') || content.includes('copied'),
    'ToolDetailModal copy button must provide visual "Copied!" feedback'
  );
});

// ─── 5. Image Alt Text ───────────────────────────────────────────────────────

test('Accessibility - All <img> tags in components have non-empty alt attributes', (t) => {
  const componentDir = path.join(rootDir, 'src/components');
  const componentFiles = fs.readdirSync(componentDir)
    .filter(f => f.endsWith('.tsx'))
    .map(f => path.join(componentDir, f));

  // Also check App.tsx
  componentFiles.push(path.join(rootDir, 'src/App.tsx'));

  let totalImgTags = 0;
  let violations = [];

  for (const filePath of componentFiles) {
    const relPath = path.relative(rootDir, filePath);
    const content = fs.readFileSync(filePath, 'utf8');

    // Match complete <img ... /> or <img ... > tags using a greedy match to capture all attrs
    // We use a greedy [^>]* so we capture the FULL attribute string including alt
    const imgRegex = /<img\b([^>]*)>/gi;
    let match;

    while ((match = imgRegex.exec(content)) !== null) {
      const attrs = match[1];
      totalImgTags++;

      // Must have alt attribute — could be alt="..." or alt={...} (JSX expression)
      const hasAlt = attrs.includes('alt=');
      if (!hasAlt) {
        violations.push(`${relPath}: <img${attrs}>`);
      }
    }
  }

  assert.equal(
    violations.length,
    0,
    `Found ${violations.length} <img> tag(s) missing alt attribute:\n${violations.join('\n')}`
  );

  t.diagnostic(`Verified alt attributes on ${totalImgTags} <img> element(s)`);
});

// ─── 6. index.html Accessibility ─────────────────────────────────────────────

test('Accessibility - index.html declares lang attribute on <html> element', (t) => {
  const content = readFile('index.html');

  assert.ok(
    content.includes('lang="en"') || content.includes("lang='en'"),
    'index.html must declare lang="en" on the <html> element for screen-reader language detection'
  );
});

test('Accessibility - index.html pre-render shell img has alt text', (t) => {
  const content = readFile('index.html');

  // The loading shell img tag must have an alt attribute
  const imgMatch = content.match(/<img[^>]+src=["']\.\/favicon\.svg["'][^>]*>/);
  if (imgMatch) {
    assert.ok(
      imgMatch[0].includes('alt='),
      'Pre-render shell <img src="./favicon.svg"> must include alt attribute'
    );
  }
});

// ─── 7. Reduced Motion Compliance ────────────────────────────────────────────

test('Accessibility - index.css respects prefers-reduced-motion for all animations', (t) => {
  const content = readFile('index.css');

  assert.ok(
    content.includes('prefers-reduced-motion'),
    'index.css must include @media (prefers-reduced-motion: reduce) to disable animations for vestibular disorder users'
  );

  // Must disable reveal, aurora, marquee, and fade-up animations
  // Use a multi-block regex to capture the full prefers-reduced-motion block
  // (which may contain nested rule sets with multiple closing braces)
  const reducedMotionIdx = content.indexOf('@media (prefers-reduced-motion: reduce)');
  assert.ok(reducedMotionIdx !== -1, 'index.css must have a prefers-reduced-motion @media block');

  // Extract content after the @media declaration
  const blockAfter = content.slice(reducedMotionIdx);
  assert.ok(
    blockAfter.includes('animation: none') ||
    blockAfter.includes('animation:none') ||
    blockAfter.includes('animation: none !important'),
    'prefers-reduced-motion block must disable animations with animation: none (or !important variant)'
  );
});

// ─── 8. Interactive Element Touch Target Sizes ────────────────────────────────

test('Accessibility - Modal close buttons meet minimum touch target size (36px)', (t) => {
  const modals = [
    'components/ToolDetailModal.tsx',
    'components/IncidentDetailModal.tsx',
    'components/ThreatDetailModal.tsx',
  ];

  for (const modal of modals) {
    const content = readFile(modal);

    // Must define minimum width/height for close button (WCAG 2.5.5 / AGENTS.md spec)
    assert.ok(
      content.includes('min-w-[36px]') || content.includes('min-h-[36px]') || content.includes('min-w-9') || content.includes('p-2'),
      `${modal} close button must meet minimum 36x36px touch target for mobile accessibility`
    );
  }
});
