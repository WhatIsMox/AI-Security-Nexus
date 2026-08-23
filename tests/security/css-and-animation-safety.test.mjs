/**
 * Security Tests — CSS & Animation Safety
 *
 * Verifies that CSS is free from injection vectors, animations respect user
 * motion preferences, the reveal system defaults to visible on mobile for 0ms
 * first paint, and layout safety constraints are in place.
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

// ─── 1. No CSS Injection Vectors ─────────────────────────────────────────────

test('CSS Safety - index.css contains no CSS expression() injection vectors', (t) => {
  const content = readFile('index.css');

  // IE CSS expression() function was an XSS vector
  assert.ok(
    !content.includes('expression('),
    'index.css must not use CSS expression() function (XSS vector in legacy IE)'
  );
});

test('CSS Safety - index.css contains no javascript: URI in url() values', (t) => {
  const content = readFile('index.css');

  assert.ok(
    !content.includes('url("javascript:') && !content.includes("url('javascript:"),
    'index.css must not contain javascript: URIs in url() values'
  );
  assert.ok(
    !content.includes('url("vbscript:') && !content.includes("url('vbscript:"),
    'index.css must not contain vbscript: URIs in url() values'
  );
});

test('CSS Safety - index.css contains no data:text/html URIs in url() values', (t) => {
  const content = readFile('index.css');

  assert.ok(
    !content.includes('data:text/html'),
    'index.css must not embed data:text/html URIs (potential XSS vector)'
  );
});

// ─── 2. Reduced Motion Compliance ────────────────────────────────────────────

test('CSS Animation Safety - prefers-reduced-motion block disables all defined animations', (t) => {
  const content = readFile('index.css');

  // Must contain the media query
  assert.ok(
    content.includes('@media (prefers-reduced-motion: reduce)'),
    'index.css must include @media (prefers-reduced-motion: reduce) for vestibular disorder users'
  );

  // Extract the reduced-motion block
  const reducedBlock = content.match(/@media\s*\(\s*prefers-reduced-motion:\s*reduce\s*\)\s*\{([\s\S]*?)\}/);
  assert.ok(reducedBlock, 'prefers-reduced-motion block must be parseable');

  const blockContent = reducedBlock[1];

  // All animation classes defined in the file must be disabled in this block
  const animationClassesInFile = [
    '.animate-aurora-a',
    '.animate-aurora-b',
    '.animate-aurora-c',
    '.animate-marquee',
    '.animate-marquee-reverse',
    '.animate-fade-up',
  ];

  for (const cls of animationClassesInFile) {
    assert.ok(
      blockContent.includes(cls) || content.match(new RegExp(`${cls.replace('.', '\\.')}[^{]*\\{[^}]*animation:\\s*none`, 'i')),
      `prefers-reduced-motion block must disable ${cls}`
    );
  }
});

test('CSS Animation Safety - .reveal class defaults to opacity:1 and transform:none outside media query', (t) => {
  const content = readFile('index.css');

  // The .reveal class must have a default (outside media queries) that is visible
  // This prevents blank-screen on mobile where IntersectionObserver may not fire
  assert.ok(content.includes('.reveal'), 'index.css must define .reveal class');

  // Find the first .reveal definition (not inside a media query)
  const revealDefaultMatch = content.match(/\.reveal\s*\{([^}]*)\}/);
  assert.ok(revealDefaultMatch, '.reveal class must have a top-level definition');

  const revealProps = revealDefaultMatch[1];
  assert.ok(
    revealProps.includes('opacity: 1') || revealProps.includes('opacity:1'),
    '.reveal default (outside media query) must set opacity: 1 for 0ms mobile first paint'
  );
  assert.ok(
    revealProps.includes('transform: none') || revealProps.includes('transform:none'),
    '.reveal default (outside media query) must set transform: none for 0ms mobile first paint'
  );
});

test('CSS Animation Safety - .reveal hidden state is only applied at min-width: 768px', (t) => {
  const content = readFile('index.css');

  // The opacity:0 / translateY state should only be inside a min-width media query
  const mobileRestrictedMatch = content.match(/@media\s*\(min-width:\s*768px\)\s*\{([^}]*\.reveal[^}]*\{[^}]*opacity:\s*0[^}]*\})/s);
  assert.ok(
    mobileRestrictedMatch,
    '.reveal opacity:0 state must be restricted to @media (min-width: 768px) to avoid blank-screen on mobile'
  );
});

// ─── 3. Layout Safety Constraints ────────────────────────────────────────────

test('CSS Layout Safety - body sets min-width: 320px to prevent extreme viewport abuse', (t) => {
  const content = readFile('index.css');

  assert.ok(
    content.includes('min-width: 320px'),
    'body must set min-width: 320px to handle minimum supported screen width'
  );
});

test('CSS Layout Safety - overflow-x: hidden on html and body prevents horizontal scroll attacks', (t) => {
  const content = readFile('index.css');

  assert.ok(
    content.includes('overflow-x: hidden'),
    'index.css must set overflow-x: hidden on html/body to prevent horizontal scroll caused by content overflow'
  );
});

// ─── 4. GPU Acceleration Safety ──────────────────────────────────────────────

test('CSS Animation Safety - .gpu-accelerated does not use transform-based scroll jacking', (t) => {
  const content = readFile('index.css');

  assert.ok(content.includes('.gpu-accelerated'), 'index.css must define .gpu-accelerated utility');

  const gpuBlock = content.match(/\.gpu-accelerated\s*\{([^}]+)\}/);
  assert.ok(gpuBlock, '.gpu-accelerated block must be parseable');

  // Must only use harmless transform and backface-visibility for compositing
  const props = gpuBlock[1];
  assert.ok(
    props.includes('transform: translateZ(0)') || props.includes('transform:translateZ(0)'),
    '.gpu-accelerated must use transform: translateZ(0) for GPU layer promotion'
  );
  assert.ok(
    !props.includes('transform: rotate') &&
    !props.includes('transform: scale') &&
    !props.includes('position: fixed'),
    '.gpu-accelerated must not override position or apply visual transforms that could cause layout shifts'
  );
});

// ─── 5. Tailwind Directives Ordering ─────────────────────────────────────────

test('CSS Structure - index.css uses correct Tailwind directive order (@base, @components, @utilities)', (t) => {
  const content = readFile('index.css');

  const baseIdx = content.indexOf('@tailwind base');
  const componentsIdx = content.indexOf('@tailwind components');
  const utilitiesIdx = content.indexOf('@tailwind utilities');

  assert.ok(baseIdx !== -1, 'index.css must include @tailwind base directive');
  assert.ok(componentsIdx !== -1, 'index.css must include @tailwind components directive');
  assert.ok(utilitiesIdx !== -1, 'index.css must include @tailwind utilities directive');

  assert.ok(baseIdx < componentsIdx, '@tailwind base must come before @tailwind components');
  assert.ok(componentsIdx < utilitiesIdx, '@tailwind components must come before @tailwind utilities');
});

// ─── 6. Scrollbar Styles ─────────────────────────────────────────────────────

test('CSS Safety - .scrollbar-hide uses standard browser prefixes without JS-based scroll interception', (t) => {
  const content = readFile('index.css');

  assert.ok(content.includes('.scrollbar-hide'), 'index.css must define .scrollbar-hide utility');

  // The scrollbar hiding implementation may be split across two rules:
  // .scrollbar-hide::-webkit-scrollbar { display: none; }  → hides webkit scrollbar
  // .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }  → hides FF/IE scrollbars
  // Check that at least one CSS-only hiding mechanism is used anywhere around the selector
  assert.ok(
    content.includes('-webkit-scrollbar') ||
    content.includes('scrollbar-width') ||
    content.includes('-ms-overflow-style'),
    '.scrollbar-hide must use CSS scrollbar hiding properties (-webkit-scrollbar, scrollbar-width, or -ms-overflow-style)'
  );
  assert.ok(
    !content.match(/\.scrollbar-hide[\s\S]*?javascript/),
    '.scrollbar-hide must not reference JavaScript evaluation'
  );
});

// ─── 7. Font Safety (Font Loading Strategy) ───────────────────────────────────

test('CSS Safety - body uses a web-safe fallback font stack', (t) => {
  const content = readFile('index.css');

  // body font-family must declare a fallback after the primary web font
  const bodyBlock = content.match(/body\s*\{([^}]*)\}/);
  assert.ok(bodyBlock, 'index.css must define body styles');

  const bodyProps = bodyBlock[1];
  assert.ok(
    bodyProps.includes('sans-serif'),
    'body font-family must include sans-serif fallback for font loading failure scenarios'
  );
});
