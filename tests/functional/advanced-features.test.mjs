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

  // Tool selection integration
  assert.ok(searchModalContent.includes('onSelectTool'), 'GlobalSearchModal must support onSelectTool');
  assert.ok(searchModalContent.includes('getEnrichedTool'), 'GlobalSearchModal must enrich tools with verified metadata');
  assert.ok(appContent.includes('onSelectTool={(tool) => setActiveModalTool(tool)}'), 'App.tsx must open ToolDetailModal when tool selected in search');

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
  assert.ok(auditContent.includes("sortMethod === 'severity'"), 'Audit checklist must implement sorting by severity / criticality');
  assert.ok(auditContent.includes('getRiskWeight'), 'Audit checklist must assign risk weights for criticality sorting');
  
  // Verify data safety interlocks
  assert.ok(auditContent.includes('window.confirm'), 'Audit checklist must use window.confirm before resetting all data to prevent accidental loss');
  assert.ok(auditContent.includes('handleReset'), 'Audit checklist must implement handleReset functionality');

  // Verify interactive state updates
  assert.ok(auditContent.includes('handleStatusChange'), 'Audit checklist must handle individual test status updates');
  assert.ok(auditContent.includes('handleNotesChange'), 'Audit checklist must handle individual test note updates');
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

  // Dashboard homepage navigation verification
  const dashboardContent = readFile('components/Dashboard.tsx');
  assert.ok(dashboardContent.includes('onSelectIncidents'), 'Dashboard must support onSelectIncidents callback');
  assert.ok(dashboardContent.includes('onSelectTools'), 'Dashboard must support onSelectTools callback');
  assert.ok(dashboardContent.includes('onClick={onSelectIncidents}'), 'Dashboard Read Case Study button must trigger onSelectIncidents');
});

test('Advanced Features - Security Tool Detail Modal & Enriched Database Verification', (t) => {
  const toolModalContent = readFile('components/ToolDetailModal.tsx');
  const toolCatalogContent = readFile('tool_details_catalog.ts');
  const toolsViewContent = readFile('components/ToolsDirectoryView.tsx');
  const owaspViewContent = readFile('components/OwaspTop10View.tsx');

  // Verify Tool Detail Modal accessibility & interactions
  assert.ok(toolModalContent.includes('role="dialog"'), 'ToolDetailModal must specify role="dialog"');
  assert.ok(toolModalContent.includes('aria-modal="true"'), 'ToolDetailModal must specify aria-modal="true"');
  assert.ok(toolModalContent.includes("e.key === 'Escape'"), 'ToolDetailModal must listen to Escape key to close');
  assert.ok(toolModalContent.includes('navigator.clipboard.writeText'), 'ToolDetailModal must implement copy command');
  assert.ok(toolModalContent.includes('rel="noopener noreferrer"'), 'ToolDetailModal external links must specify rel="noopener noreferrer"');
  assert.ok(toolModalContent.includes('target="_blank"'), 'ToolDetailModal external links must specify target="_blank"');

  // Verify Enriched Database coverage
  const keyTools = ['garak', 'PyRIT', 'promptfoo', 'Giskard', 'NVIDIA NeMo Guardrails', 'Presidio', 'ModelScan', 'Trivy', 'Open Policy Agent (OPA)'];
  for (const toolName of keyTools) {
    assert.ok(toolCatalogContent.includes(toolName), `tool_details_catalog.ts must contain verified metadata for '${toolName}'`);
  }

  assert.ok(toolCatalogContent.includes('longDescription'), 'Tool database entries must have longDescription');
  assert.ok(toolCatalogContent.includes('typicalUseCase'), 'Tool database entries must have typicalUseCase');
  assert.ok(toolCatalogContent.includes('keyFeatures'), 'Tool database entries must have keyFeatures');
  assert.ok(toolCatalogContent.includes('installationOrQuickstart'), 'Tool database entries must have installationOrQuickstart');
  assert.ok(toolCatalogContent.includes('getEnrichedTool'), 'tool_details_catalog.ts must export getEnrichedTool');

  // Verify integration in views
  assert.ok(toolsViewContent.includes('<ToolDetailModal'), 'ToolsDirectoryView must render ToolDetailModal');
  assert.ok(toolsViewContent.includes('setSelectedTool'), 'ToolsDirectoryView must manage selectedTool state');
  assert.ok(owaspViewContent.includes('<ToolDetailModal'), 'OwaspTop10View must render ToolDetailModal');
  assert.ok(owaspViewContent.includes('setSelectedTool'), 'OwaspTop10View must manage selectedTool state');
});

test('Advanced Features - Real-World Incident Detail Modal & Enriched Intelligence Verification', (t) => {
  const incidentModalContent = readFile('components/IncidentDetailModal.tsx');
  const incidentCatalogContent = readFile('incident_details_catalog.ts');
  const incidentsViewContent = readFile('components/IncidentsDirectoryView.tsx');
  const searchModalContent = readFile('components/GlobalSearchModal.tsx');
  const appContent = readFile('App.tsx');

  // Verify Incident Detail Modal accessibility & layout
  assert.ok(incidentModalContent.includes('role="dialog"'), 'IncidentDetailModal must specify role="dialog"');
  assert.ok(incidentModalContent.includes('aria-modal="true"'), 'IncidentDetailModal must specify aria-modal="true"');
  assert.ok(incidentModalContent.includes("e.key === 'Escape'"), 'IncidentDetailModal must listen to Escape key');
  assert.ok(incidentModalContent.includes('rel="noopener noreferrer"'), 'IncidentDetailModal links must specify rel="noopener noreferrer"');
  assert.ok(incidentModalContent.includes('target="_blank"'), 'IncidentDetailModal links must specify target="_blank"');

  // Verify rich content sections in modal
  assert.ok(incidentModalContent.includes('Attack Vector & Technical Mechanics'), 'Must render Attack Vector section');
  assert.ok(incidentModalContent.includes('Security & Operational Impact'), 'Must render Impact section');
  assert.ok(incidentModalContent.includes('Recovery Timeline & Response'), 'Must render Recovery Timeline section');
  assert.ok(incidentModalContent.includes('Repercussions & Legal Fallout'), 'Must render Repercussions section');
  assert.ok(incidentModalContent.includes('Remediation & Defensive Architecture'), 'Must render Remediation section');
  assert.ok(incidentModalContent.includes('Key Takeaway for AI Security Practitioners'), 'Must render Lessons Learned section');

  // Verify Enriched Database coverage
  assert.ok(incidentCatalogContent.includes('getEnrichedIncident'), 'incident_details_catalog.ts must export getEnrichedIncident');
  assert.ok(incidentCatalogContent.includes('INCIDENT_DATABASE'), 'incident_details_catalog.ts must export INCIDENT_DATABASE');

  // Verify integration in views
  assert.ok(incidentsViewContent.includes('<IncidentDetailModal'), 'IncidentsDirectoryView must render IncidentDetailModal');
  assert.ok(incidentsViewContent.includes('setSelectedIncident'), 'IncidentsDirectoryView must manage selectedIncident state');
  assert.ok(searchModalContent.includes('onSelectIncident'), 'GlobalSearchModal must support onSelectIncident');
  assert.ok(appContent.includes('<IncidentDetailModal'), 'App.tsx must render IncidentDetailModal');
  assert.ok(appContent.includes('onSelectIncident={(incident) => setActiveModalIncident(incident)}'), 'App.tsx must handle search incident selection');
});


