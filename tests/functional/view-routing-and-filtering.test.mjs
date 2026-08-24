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

test('Functional - App Router View Transitions', (t) => {
  const appContent = readFile('App.tsx');

  // Verify all views are supported in currentView state type
  const expectedViews = [
    'dashboard',
    'tests',
    'detail',
    'threat-model',
    'owasp-top10',
    'owasp-ml-top10',
    'owasp-agent-top10',
    'owasp-saif-top10',
    'owasp-mcp-top10',
    'secure-mcp-guide',
    'genai-data-security',
    'audit-checklist',
    'tools',
    'incidents'
  ];

  for (const view of expectedViews) {
    assert.ok(appContent.includes(`'${view}'`), `App.tsx should support view '${view}'`);
  }

  // Verify handleNavigateToOwasp routing logic for various prefixes
  assert.ok(appContent.includes('id.startsWith("ML")'), 'ML IDs route to owasp-ml-top10');
  assert.ok(appContent.includes('id.startsWith("ASI") || id.startsWith("AST")'), 'Agentic IDs route to owasp-agent-top10');
  assert.ok(appContent.includes('id.startsWith("SAIF")'), 'SAIF IDs route to owasp-saif-top10');
  assert.ok(appContent.includes('id.startsWith("MCP")'), 'MCP IDs route to owasp-mcp-top10');
});

test('Functional - Pillar Filtering Algorithm', (t) => {
  const testsContent = readFile('data_tests.ts');
  const agenticContent = readFile('data_agentic.ts');

  // Extract test items roughly
  const standardAppTests = (testsContent.match(/pillar:\s*Pillar\.APP/g) || []).length;
  const standardModelTests = (testsContent.match(/pillar:\s*Pillar\.MODEL/g) || []).length;
  const standardInfraTests = (testsContent.match(/pillar:\s*Pillar\.INFRA/g) || []).length;
  const standardDataTests = (testsContent.match(/pillar:\s*Pillar\.DATA/g) || []).length;

  const agenticAppTests = (agenticContent.match(/pillar:\s*Pillar\.APP/g) || []).length;
  const agenticInfraTests = (agenticContent.match(/pillar:\s*Pillar\.INFRA/g) || []).length;

  assert.ok(standardAppTests + agenticAppTests > 0, 'APP pillar must contain tests');
  assert.ok(standardModelTests > 0, 'MODEL pillar must contain tests');
  assert.ok(standardInfraTests + agenticInfraTests > 0, 'INFRA pillar must contain tests');
  assert.ok(standardDataTests > 0, 'DATA pillar must contain tests');
});

test('Functional - Filtering and Sorting Logic in Views', (t) => {
  const testListContent = readFile('components/TestList.tsx');
  const dsgaiViewContent = readFile('components/GenAiDataSecurityView.tsx');
  const top10ViewContent = readFile('components/OwaspTop10View.tsx');

  assert.ok(testListContent.includes('filterType') && testListContent.includes('sortMethod'), 'TestList must implement filtering and sorting');
  assert.ok(dsgaiViewContent.includes('searchQuery') || dsgaiViewContent.includes('filter'), 'GenAiDataSecurityView must implement searchQuery or filtering');
  assert.ok(top10ViewContent.includes('initialExpandedId') || top10ViewContent.includes('expandedId'), 'OwaspTop10View must support expanding entries');
});

test('Functional - Page View Transitions & Modal Animation System', (t) => {
  const indexCss = readFile('index.css');
  const appContent = readFile('App.tsx');
  const agenticViewContent = readFile('components/AgenticTop10View.tsx');
  const toolModalContent = readFile('components/ToolDetailModal.tsx');
  const incidentModalContent = readFile('components/IncidentDetailModal.tsx');
  const threatModalContent = readFile('components/ThreatDetailModal.tsx');
  const searchModalContent = readFile('components/GlobalSearchModal.tsx');

  // 1. CSS Keyframes and Animation Classes
  assert.ok(indexCss.includes('@keyframes page-enter'), 'index.css must define @keyframes page-enter');
  assert.ok(indexCss.includes('.animate-page-enter'), 'index.css must define .animate-page-enter class');
  assert.ok(indexCss.includes('.page-view-transition'), 'index.css must define .page-view-transition class');
  assert.ok(indexCss.includes('@keyframes modal-backdrop-enter'), 'index.css must define @keyframes modal-backdrop-enter');
  assert.ok(indexCss.includes('@keyframes modal-card-enter'), 'index.css must define @keyframes modal-card-enter');
  assert.ok(indexCss.includes('.animate-modal-backdrop'), 'index.css must define .animate-modal-backdrop class');
  assert.ok(indexCss.includes('.animate-modal-card'), 'index.css must define .animate-modal-card class');

  // 2. Accessibility & Reduced Motion
  assert.ok(indexCss.includes('@media (prefers-reduced-motion: reduce)'), 'index.css must declare prefers-reduced-motion media query');
  assert.ok(indexCss.includes('.animate-page-enter') && indexCss.includes('animation: none !important;'), 'Reduced motion must disable page animations');

  // 3. Universal Page Transition Coverage in App.tsx
  assert.ok(appContent.includes('className="page-view-transition animate-page-enter"'), 'App.tsx must wrap all views in animated transition container');
  assert.ok(appContent.includes('key={`${currentView}-${activePillar}-'), 'App.tsx must bind view transition key to route state');

  // 4. Sub-view panel animations in AgenticTop10View
  assert.ok(agenticViewContent.includes('className="page-view-transition animate-page-enter"'), 'AgenticTop10View must wrap tab panels in page transition classes');

  // 5. Modal Dialog animations across all modal components
  assert.ok(toolModalContent.includes('animate-modal-backdrop'), 'ToolDetailModal must use animate-modal-backdrop');
  assert.ok(toolModalContent.includes('animate-modal-card'), 'ToolDetailModal must use animate-modal-card');

  assert.ok(incidentModalContent.includes('animate-modal-backdrop'), 'IncidentDetailModal must use animate-modal-backdrop');
  assert.ok(incidentModalContent.includes('animate-modal-card'), 'IncidentDetailModal must use animate-modal-card');

  assert.ok(threatModalContent.includes('animate-modal-backdrop'), 'ThreatDetailModal must use animate-modal-backdrop');
  assert.ok(threatModalContent.includes('animate-modal-card'), 'ThreatDetailModal must use animate-modal-card');

  assert.ok(searchModalContent.includes('animate-modal-backdrop'), 'GlobalSearchModal must use animate-modal-backdrop');
  assert.ok(searchModalContent.includes('animate-modal-card'), 'GlobalSearchModal must use animate-modal-card');
});

test('Functional - Dashboard Hero and Footer Signature', (t) => {
  const dashboardContent = readFile('components/Dashboard.tsx');
  assert.ok(dashboardContent.includes('Made with'), 'Dashboard footer must render author signature');
  assert.ok(dashboardContent.includes('Gabriele Mossino'), 'Dashboard footer must credit Gabriele Mossino');
  assert.ok(dashboardContent.includes('❤️'), 'Dashboard footer must include the heart emoticon');
});



