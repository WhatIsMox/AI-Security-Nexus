import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const ROOT_DIR = process.cwd();

test('Brand Assets - Icon Files Exist and Are Valid', () => {
  const iconPngPath = path.join(ROOT_DIR, 'public', 'icon.png');
  const faviconSvgPath = path.join(ROOT_DIR, 'public', 'favicon.svg');
  const faviconPngPath = path.join(ROOT_DIR, 'public', 'favicon.png');
  const appleTouchPath = path.join(ROOT_DIR, 'public', 'apple-touch-icon.png');

  assert.ok(fs.existsSync(iconPngPath), 'public/icon.png must exist');
  assert.ok(fs.existsSync(faviconSvgPath), 'public/favicon.svg must exist');
  assert.ok(fs.existsSync(faviconPngPath), 'public/favicon.png must exist');
  assert.ok(fs.existsSync(appleTouchPath), 'public/apple-touch-icon.png must exist');

  const iconStat = fs.statSync(iconPngPath);
  const svgStat = fs.statSync(faviconSvgPath);
  assert.ok(iconStat.size > 10000, 'icon.png must be a high-resolution asset (>10KB)');
  assert.ok(svgStat.size > 10000, 'favicon.svg must contain embedded high-fidelity data (>10KB)');
});

test('Brand Assets - Favicon SVG Pixel-to-Pixel SHA-256 Fidelity with Real Logo', () => {
  const iconPng = fs.readFileSync(path.join(ROOT_DIR, 'public', 'icon.png'));
  const iconSha256 = crypto.createHash('sha256').update(iconPng).digest('hex');

  const svgContent = fs.readFileSync(path.join(ROOT_DIR, 'public', 'favicon.svg'), 'utf8');
  assert.ok(svgContent.includes('<svg'), 'favicon.svg must contain valid SVG tag');
  assert.ok(svgContent.includes('<image'), 'favicon.svg must contain <image> embedding tag');

  const match = svgContent.match(/href="data:image\/png;base64,([^"]+)"/);
  assert.ok(match && match[1], 'favicon.svg must embed valid base64 PNG data');

  const extractedPng = Buffer.from(match[1], 'base64');
  const extractedSha256 = crypto.createHash('sha256').update(extractedPng).digest('hex');

  assert.strictEqual(
    extractedSha256,
    iconSha256,
    `favicon.svg embedded data must match public/icon.png bit-for-bit (Expected ${iconSha256}, got ${extractedSha256})`
  );
});

test('Brand Assets - HTML & React Component Integrations', () => {
  const indexHtml = fs.readFileSync(path.join(ROOT_DIR, 'index.html'), 'utf8');
  assert.ok(indexHtml.includes('rel="icon" type="image/svg+xml" href="./favicon.svg"'), 'index.html must reference favicon.svg');
  assert.ok(indexHtml.includes('rel="alternate icon" type="image/png" href="./icon.png"'), 'index.html must reference icon.png');
  assert.ok(indexHtml.includes('rel="apple-touch-icon" href="./icon.png"'), 'index.html must reference apple-touch-icon');

  const sidebarContent = fs.readFileSync(path.join(ROOT_DIR, 'src', 'components', 'Sidebar.tsx'), 'utf8');
  assert.ok(sidebarContent.includes('favicon.svg'), 'Sidebar.tsx must render the official brand emblem');

  const appContent = fs.readFileSync(path.join(ROOT_DIR, 'src', 'App.tsx'), 'utf8');
  assert.ok(appContent.includes('favicon.svg'), 'App.tsx mobile header must render the official brand emblem');
});
