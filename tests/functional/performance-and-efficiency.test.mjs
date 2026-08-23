import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../');

function readFile(relPath) {
  return fs.readFileSync(path.join(rootDir, relPath), 'utf-8');
}

test('Performance & Efficiency - Dynamic Route-Level Code Splitting', (t) => {
  const appContent = readFile('App.tsx');
  
  // Assert secondary views are lazy-loaded to minimize initial bundle size
  assert.ok(appContent.includes("lazy(") || appContent.includes("React.lazy("), 'App.tsx must use lazy for code-splitting');
  assert.ok(appContent.includes("import('./components/ThreatModelling')"), 'ThreatModelling must be lazy loaded');
  assert.ok(appContent.includes("import('./components/GenAiDataSecurityView')"), 'GenAiDataSecurityView must be lazy loaded');
  assert.ok(appContent.includes("import('./components/AuditChecklistView')"), 'AuditChecklistView must be lazy loaded');
  assert.ok(appContent.includes("import('./components/ToolsDirectoryView')"), 'ToolsDirectoryView must be lazy loaded');
  assert.ok(appContent.includes("import('./components/IncidentsDirectoryView')"), 'IncidentsDirectoryView must be lazy loaded');
  assert.ok(appContent.includes("Suspense fallback="), 'App.tsx must wrap lazy views in Suspense');
});

test('Performance & Efficiency - Vite Manual Chunking Configuration', (t) => {
  const viteConfig = readFile('vite.config.ts');
  
  // Assert granular chunking for heavy intelligence catalogs and framework data
  assert.ok(viteConfig.includes('manualChunks'), 'vite.config.ts must declare manualChunks for code splitting');
  assert.ok(viteConfig.includes('security-intelligence-db'), 'Must isolate security intelligence database into dedicated chunk');
  assert.ok(viteConfig.includes('frameworks-data'), 'Must isolate framework data into dedicated chunk');
});

test('Performance & Efficiency - CSS Layout Containment & Content Visibility', (t) => {
  const indexCss = readFile('index.css');
  
  // Assert content-visibility rule for off-screen rendering bypass
  assert.ok(indexCss.includes('.content-auto'), 'index.css must define .content-auto utility');
  assert.ok(indexCss.includes('content-visibility: auto;'), 'content-auto must declare content-visibility: auto');
  assert.ok(indexCss.includes('contain-intrinsic-size:'), 'content-auto must define contain-intrinsic-size placeholder');
  
  // Assert list components apply .content-auto
  const incidentsView = readFile('components/IncidentsDirectoryView.tsx');
  assert.ok(incidentsView.includes('content-auto'), 'IncidentsDirectoryView cards must specify content-auto');

  const toolsView = readFile('components/ToolsDirectoryView.tsx');
  assert.ok(toolsView.includes('content-auto'), 'ToolsDirectoryView cards must specify content-auto');

  const testListView = readFile('components/TestList.tsx');
  assert.ok(testListView.includes('content-auto'), 'TestList cards must specify content-auto');

  const auditView = readFile('components/AuditChecklistView.tsx');
  assert.ok(auditView.includes('content-auto'), 'AuditChecklistView rows must specify content-auto');
});

test('Performance & Efficiency - Omnisearch Precomputed Indexing & Token Search', (t) => {
  const searchContent = readFile('components/GlobalSearchModal.tsx');
  
  // Assert precomputed lowercase search token and index caching
  assert.ok(searchContent.includes('searchText:'), 'GlobalSearchModal items must have precomputed searchText token');
  assert.ok(searchContent.includes('cachedSearchIndex'), 'GlobalSearchModal must memoize static search database at module level');
  assert.ok(searchContent.includes('item.searchText.includes('), 'Search filtering must match against precomputed token');
});

test('Performance & Efficiency - Network & Asset Resource Hints', (t) => {
  const indexHtml = readFile('index.html');
  
  // Assert DNS prefetch and font preconnects
  assert.ok(indexHtml.includes('rel="dns-prefetch" href="https://fonts.googleapis.com"'), 'index.html must prefetch google fonts DNS');
  assert.ok(indexHtml.includes('rel="preconnect" href="https://fonts.googleapis.com"'), 'index.html must preconnect to google fonts');
  assert.ok(indexHtml.includes('rel="preconnect" href="https://fonts.gstatic.com"'), 'index.html must preconnect to gstatic');
  assert.ok(indexHtml.includes('display=swap'), 'Font stylesheet must specify display=swap to prevent FOIT');
});

test('Performance & Efficiency - Non-Blocking Analytics & 0ms Loading Shell', (t) => {
  const indexHtml = readFile('index.html');
  
  // Assert analytics deferred
  assert.ok(indexHtml.includes("loadAnalytics") && indexHtml.includes("addEventListener('load'"), 'Analytics loader must attach to load event');
  assert.ok(indexHtml.includes("s.async = true"), 'Analytics script must be asynchronous');
  assert.ok(indexHtml.includes("s.defer = true"), 'Analytics script must be deferred');
  
  // Assert inline pre-render loading shell inside #root
  assert.ok(indexHtml.includes('id="root"'), 'index.html must contain #root mount element');
  assert.ok(indexHtml.includes('Loading frameworks'), 'index.html must provide pre-render visual loading status');
  assert.ok(indexHtml.includes('AI Security Nexus'), 'Pre-render shell must include brand title for 0ms initial paint');
});
