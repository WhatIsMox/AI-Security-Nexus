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

test('Advanced Features - URL Hash Routing & State Sync', (t) => {
  const appContent = readFile('App.tsx');

  // Verify hash routing parser supports all routes
  const routes = [
    'dashboard',
    'threat-model',
    'audit-checklist',
    'tools',
    'incidents',
    'secure-mcp-guide',
    'genai-data-security',
    'owasp-top10',
    'owasp-ml-top10',
    'owasp-agent-top10',
    'owasp-saif-top10',
    'owasp-mcp-top10',
    'detail/',
    'tests'
  ];

  for (const route of routes) {
    assert.ok(appContent.includes(route), `Hash router should handle route '${route}'`);
  }

  // Verify browser history event listeners (hashchange, popstate)
  assert.ok(appContent.includes("window.addEventListener('hashchange'"), 'App.tsx must listen to hashchange');
  assert.ok(appContent.includes("window.addEventListener('popstate'"), 'App.tsx must listen to popstate');
  assert.ok(appContent.includes('window.history.pushState'), 'App.tsx must synchronize state to URL hash');
});

test('Advanced Features - Global Omnisearch (Cmd+K) Component & Shortcuts', (t) => {
  const searchModalContent = readFile('components/GlobalSearchModal.tsx');
  const appContent = readFile('App.tsx');
  const sidebarContent = readFile('components/Sidebar.tsx');

  // Global search shortcut in App.tsx
  assert.ok(appContent.includes("e.key.toLowerCase() === 'k'"), 'App.tsx must listen to Cmd+K / Ctrl+K shortcut');
  assert.ok(appContent.includes('<GlobalSearchModal'), 'App.tsx must render GlobalSearchModal');

  // Omnisearch indexing coverage in GlobalSearchModal.tsx
  assert.ok(searchModalContent.includes('TEST_DATA'), 'GlobalSearchModal must index TEST_DATA');
  assert.ok(searchModalContent.includes('OWASP_TOP_10_DATA'), 'GlobalSearchModal must index OWASP_TOP_10_DATA');
  assert.ok(searchModalContent.includes('OWASP_ML_TOP_10_DATA'), 'GlobalSearchModal must index OWASP_ML_TOP_10_DATA');
  assert.ok(searchModalContent.includes('OWASP_AGENTIC_APPLICATIONS_DATA'), 'GlobalSearchModal must index ASI data');
  assert.ok(searchModalContent.includes('OWASP_AGENTIC_THREATS_DATA'), 'GlobalSearchModal must index AST data');
  assert.ok(searchModalContent.includes('OWASP_SAIF_THREATS_DATA'), 'GlobalSearchModal must index SAIF data');
  assert.ok(searchModalContent.includes('OWASP_MCP_TOP_10_DATA'), 'GlobalSearchModal must index MCP data');
  assert.ok(searchModalContent.includes('GENAI_DATA_SECURITY_RISKS'), 'GlobalSearchModal must index DSGAI data');
  assert.ok(searchModalContent.includes('GENAI_DSPM_CAPABILITIES'), 'GlobalSearchModal must index AI-DSPM data');
  assert.ok(searchModalContent.includes('TOOLS_BY_THREAT_ID'), 'GlobalSearchModal must index Security Tools');
  assert.ok(searchModalContent.includes('INCIDENTS_BY_THREAT_ID'), 'GlobalSearchModal must index Incidents');

  // Keyboard navigation support
  assert.ok(searchModalContent.includes("e.key === 'ArrowDown'"), 'GlobalSearchModal must support ArrowDown navigation');
  assert.ok(searchModalContent.includes("e.key === 'ArrowUp'"), 'GlobalSearchModal must support ArrowUp navigation');
  assert.ok(searchModalContent.includes("e.key === 'Enter'"), 'GlobalSearchModal must support Enter selection');
  assert.ok(searchModalContent.includes("e.key === 'Escape'"), 'GlobalSearchModal must support Escape closing');

  // Quick button in Sidebar
  assert.ok(sidebarContent.includes('Search Nexus'), 'Sidebar must include search button');
  assert.ok(sidebarContent.includes('⌘K'), 'Sidebar must display ⌘K shortcut hint');
});

test('Advanced Features - TestList Free-Text Keyword Search Bar', (t) => {
  const testListContent = readFile('components/TestList.tsx');

  assert.ok(testListContent.includes('searchQuery'), 'TestList must maintain searchQuery state');
  assert.ok(testListContent.includes('Search test cases by keyword'), 'TestList must render search input placeholder');
  assert.ok(testListContent.includes('test.objectives'), 'TestList search must check objectives');
  assert.ok(testListContent.includes('test.payloads'), 'TestList search must check attack payloads');
  assert.ok(testListContent.includes('test.mitigationStrategies'), 'TestList search must check remediations');
});

test('Advanced Features - Payload Copy to Clipboard in TestDetail', (t) => {
  const testDetailContent = readFile('components/TestDetail.tsx');

  assert.ok(testDetailContent.includes('handleCopyPayload'), 'TestDetail must implement handleCopyPayload');
  assert.ok(testDetailContent.includes('navigator.clipboard.writeText'), 'TestDetail must copy to clipboard');
  assert.ok(testDetailContent.includes('Copied!'), 'TestDetail must display Copied! visual feedback');
});

test('Advanced Features - Interactive Audit Checklist & Export Suite', (t) => {
  const auditContent = readFile('components/AuditChecklistView.tsx');

  assert.ok(auditContent.includes('localStorage.getItem'), 'Audit checklist must read from localStorage');
  assert.ok(auditContent.includes('localStorage.setItem'), 'Audit checklist must save to localStorage');
  assert.ok(auditContent.includes('exportJson'), 'Audit checklist must support JSON export');
  assert.ok(auditContent.includes('exportMarkdown'), 'Audit checklist must support Markdown assessment export');
  assert.ok(auditContent.includes('window.print()'), 'Audit checklist must support print to PDF');
  assert.ok(auditContent.includes('progressPercent'), 'Audit checklist must compute percentage progress');
});

test('Advanced Features - Consolidated Tools Matrix & Incidents Explorer Views', (t) => {
  const toolsViewContent = readFile('components/ToolsDirectoryView.tsx');
  const incidentsViewContent = readFile('components/IncidentsDirectoryView.tsx');

  // Tools Matrix verification
  assert.ok(toolsViewContent.includes('TOOLS_BY_THREAT_ID'), 'ToolsDirectoryView must import TOOLS_BY_THREAT_ID');
  assert.ok(toolsViewContent.includes('categoryFilter'), 'ToolsDirectoryView must support posture filter');
  assert.ok(toolsViewContent.includes('costFilter'), 'ToolsDirectoryView must support pricing filter');
  assert.ok(toolsViewContent.includes('mappedThreats'), 'ToolsDirectoryView must render mapped threat badges');

  // Incidents Directory verification
  assert.ok(incidentsViewContent.includes('INCIDENTS_BY_THREAT_ID'), 'IncidentsDirectoryView must import INCIDENTS_BY_THREAT_ID');
  assert.ok(incidentsViewContent.includes('frameworkFilter'), 'IncidentsDirectoryView must support framework filter');
  assert.ok(incidentsViewContent.includes('mappedThreats'), 'IncidentsDirectoryView must render mapped threat tags');
});
