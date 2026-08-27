/**
 * Build Tests — SEO & HTML Head Integrity
 *
 * Verifies that index.html implements all required SEO metadata, Open Graph tags,
 * proper accessibility declarations, and font loading strategy.
 * These affect discoverability, social sharing previews, and LCP performance.
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

// ─── 1. DOCTYPE & Document Structure ─────────────────────────────────────────

test('SEO - index.html has proper HTML5 DOCTYPE declaration', () => {
  const content = readFile('index.html');

  assert.ok(
    content.trim().toLowerCase().startsWith('<!doctype html>'),
    'index.html must begin with <!DOCTYPE html> declaration'
  );
});

test('SEO - index.html declares lang attribute on <html> element', () => {
  const content = readFile('index.html');

  assert.ok(
    content.includes('lang="en"') || content.includes("lang='en'"),
    'index.html must declare lang="en" on the <html> element for SEO and screen-reader language detection'
  );
});

// ─── 2. Title Tag ─────────────────────────────────────────────────────────────

test('SEO - index.html has a descriptive <title> tag', () => {
  const content = readFile('index.html');

  const titleMatch = content.match(/<title>([^<]+)<\/title>/i);
  assert.ok(titleMatch, 'index.html must contain a <title> element');

  const titleText = titleMatch[1].trim();
  assert.ok(titleText.length >= 10, `<title> must be at least 10 characters, found: "${titleText}"`);
  assert.ok(titleText.length <= 70, `<title> should be ≤70 characters for SEO (found ${titleText.length} chars): "${titleText}"`);
  assert.ok(
    titleText.toLowerCase().includes('security') || titleText.toLowerCase().includes('owasp') || titleText.toLowerCase().includes('ai'),
    `<title> must reference the product domain (security/AI/OWASP): "${titleText}"`
  );
});

// ─── 3. Meta Description ──────────────────────────────────────────────────────

test('SEO - index.html has a meaningful meta description (≥50 chars)', () => {
  const content = readFile('index.html');

  const metaDescMatch = content.match(/<meta\s+name=["']description["']\s+content=["']([^"']+)["']/i) ||
                        content.match(/<meta\s+content=["']([^"']+)["']\s+name=["']description["']/i);

  assert.ok(metaDescMatch, 'index.html must contain a <meta name="description"> element');

  const description = metaDescMatch[1].trim();
  assert.ok(
    description.length >= 50,
    `Meta description must be at least 50 characters, found ${description.length} chars: "${description}"`
  );
  assert.ok(
    description.length <= 160,
    `Meta description should be ≤160 characters for SEO (found ${description.length} chars)`
  );
});

// ─── 4. Open Graph Meta Tags ──────────────────────────────────────────────────

test('SEO - index.html has og:title Open Graph tag', () => {
  const content = readFile('index.html');

  const ogTitle = content.match(/property=["']og:title["']\s+content=["']([^"']+)["']/i) ||
                  content.match(/content=["']([^"']+)["']\s+property=["']og:title["']/i);

  assert.ok(ogTitle, 'index.html must have og:title Open Graph meta tag for social sharing previews');
  assert.ok(ogTitle[1].trim().length >= 5, 'og:title must be non-trivial (≥5 chars)');
});

test('SEO - index.html has og:description Open Graph tag', () => {
  const content = readFile('index.html');

  const ogDesc = content.match(/property=["']og:description["']\s+content=["']([^"']+)["']/i) ||
                 content.match(/content=["']([^"']+)["']\s+property=["']og:description["']/i);

  assert.ok(ogDesc, 'index.html must have og:description Open Graph meta tag');
  assert.ok(ogDesc[1].trim().length >= 10, 'og:description must be non-trivial (≥10 chars)');
});

test('SEO - index.html has og:image Open Graph tag', () => {
  const content = readFile('index.html');

  const ogImage = content.match(/property=["']og:image["']\s+content=["']([^"']+)["']/i) ||
                  content.match(/content=["']([^"']+)["']\s+property=["']og:image["']/i);

  assert.ok(ogImage, 'index.html must have og:image Open Graph meta tag for social sharing card previews');

  const imageSrc = ogImage[1].trim();
  assert.ok(imageSrc.length > 0, 'og:image content must be non-empty');
  // Must be a relative URL or absolute URL (not javascript: or data:)
  assert.ok(
    !imageSrc.startsWith('javascript:') && !imageSrc.startsWith('data:text/html'),
    `og:image must not use javascript: or dangerous data: URI: "${imageSrc}"`
  );
});

// ─── 5. Favicon & Icon Links ─────────────────────────────────────────────────

test('SEO - index.html references favicon.svg as primary icon', () => {
  const content = readFile('index.html');

  assert.ok(
    content.includes('rel="icon"') && content.includes('favicon.svg'),
    'index.html must reference favicon.svg as the primary icon for modern browsers'
  );
});

test('SEO - index.html references icon.png as fallback and Apple touch icon', () => {
  const content = readFile('index.html');

  assert.ok(
    content.includes('rel="alternate icon"') || content.includes('rel="shortcut icon"'),
    'index.html must reference icon.png as an alternate/fallback icon'
  );
  assert.ok(
    content.includes('rel="apple-touch-icon"'),
    'index.html must reference apple-touch-icon for iOS home screen bookmarks'
  );
});

// ─── 6. Charset & Viewport ───────────────────────────────────────────────────

test('SEO - index.html declares UTF-8 charset', () => {
  const content = readFile('index.html');

  assert.ok(
    content.includes('charset="UTF-8"') || content.includes("charset='UTF-8'"),
    'index.html must declare charset="UTF-8" in <meta charset>'
  );
});

test('SEO - index.html has viewport meta for mobile-responsive rendering', () => {
  const content = readFile('index.html');

  assert.ok(content.includes('name="viewport"'), 'index.html must include <meta name="viewport">');
  assert.ok(content.includes('width=device-width'), 'viewport meta must set width=device-width');
  assert.ok(content.includes('initial-scale=1.0') || content.includes('initial-scale=1'), 'viewport meta must set initial-scale=1.0');
});

// ─── 7. Font Loading Performance ──────────────────────────────────────────────

test('SEO / Performance - index.html preconnects to Google Fonts for LCP optimization', () => {
  const content = readFile('index.html');

  assert.ok(
    content.includes('rel="preconnect" href="https://fonts.googleapis.com"'),
    'index.html must preconnect to fonts.googleapis.com for LCP font loading optimization'
  );
  assert.ok(
    content.includes('rel="preconnect" href="https://fonts.gstatic.com"'),
    'index.html must preconnect to fonts.gstatic.com for font file loading'
  );
  assert.ok(
    content.includes('rel="dns-prefetch"'),
    'index.html must include dns-prefetch hints as a fallback for older browsers'
  );
});

test('SEO / Performance - Google Fonts stylesheet uses display=swap to prevent FOIT', () => {
  const content = readFile('index.html');

  // Match the full <link> tag for the font stylesheet (the one with rel="stylesheet")
  // using a broader pattern that captures the full tag including href
  const fontLink = content.match(/<link[^>]+fonts\.googleapis\.com\/css[^>]*>/i);
  assert.ok(fontLink, 'index.html must include a Google Fonts <link> stylesheet');

  // The href may contain &amp; (HTML-encoded) or & (raw) before display=swap
  const hrefValue = fontLink[0];
  assert.ok(
    hrefValue.includes('display=swap') || hrefValue.includes('display%3Dswap'),
    'Google Fonts URL must include display=swap to prevent Flash of Invisible Text (FOIT)'
  );
});

// ─── 8. Root Element & Pre-Render Shell ──────────────────────────────────────

test('SEO - index.html has #root mount element with inline pre-render shell', () => {
  const content = readFile('index.html');

  assert.ok(content.includes('id="root"'), 'index.html must have <div id="root"> as React mount target');

  // The pre-render shell should contain brand name for 0ms first paint
  const rootMatch = content.match(/<div id="root">([\s\S]*?)<\/div>/);
  assert.ok(rootMatch, 'index.html must have content inside #root for pre-render shell');
  assert.ok(
    rootMatch[1].includes('AI Security') || rootMatch[1].includes('OWASP') || rootMatch[1].includes('Loading'),
    'Pre-render shell inside #root must include brand text for immediate user feedback'
  );
});

// ─── 9. Module Entry Point ────────────────────────────────────────────────────

test('SEO - index.html references Vite entry point as type="module" script', () => {
  const content = readFile('index.html');

  assert.ok(
    content.includes('type="module"') && content.includes('index.tsx'),
    'index.html must reference index.tsx as type="module" script for Vite SPA bootstrapping'
  );
});

// ─── 10. No Synchronous Render-Blocking Scripts ──────────────────────────────

test('SEO / Performance - Analytics script is non-blocking (async + defer)', () => {
  const content = readFile('index.html');

  // The analytics script must be async and/or deferred
  if (content.includes('stats.byreference.net') || content.includes('plausible')) {
    assert.ok(
      content.includes('s.async = true') || content.includes('async'),
      'Analytics script must be marked async to avoid blocking page render'
    );
    assert.ok(
      content.includes("addEventListener('load'") || content.includes('defer') || content.includes('s.defer'),
      'Analytics script must be deferred (via load event or defer attribute) to prevent LCP delay'
    );
  }
});
