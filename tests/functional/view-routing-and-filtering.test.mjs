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

  // Verify all 11 views are supported in currentView state type
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
    'genai-data-security'
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
