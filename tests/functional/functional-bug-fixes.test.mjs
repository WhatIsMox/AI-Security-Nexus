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

test('Bug Fix 1: GlobalSearchModal a11y label targets existing title element', (t) => {
  const content = readFile('components/GlobalSearchModal.tsx');
  assert.ok(content.includes('aria-labelledby="global-search-title"'), 'Modal must declare aria-labelledby');
  assert.ok(content.includes('id="global-search-title"'), 'Modal must render an element with id="global-search-title" for screen reader compliance');
  t.diagnostic('Verified GlobalSearchModal accessibility label target element');
});

test('Bug Fix 2: GlobalSearchModal dynamic tab category counts', (t) => {
  const content = readFile('components/GlobalSearchModal.tsx');
  assert.ok(!content.includes('Threats (89)'), 'Modal must not contain hardcoded "Threats (89)"');
  assert.ok(content.includes('categoryCounts'), 'Modal must compute dynamic categoryCounts');
  assert.ok(content.includes('categoryCounts.tests'), 'Modal must display dynamic tests count');
  assert.ok(content.includes('categoryCounts.threats'), 'Modal must display dynamic threats count');
  assert.ok(content.includes('categoryCounts.tools'), 'Modal must display dynamic tools count');
  assert.ok(content.includes('categoryCounts.incidents'), 'Modal must display dynamic incidents count');
  t.diagnostic('Verified dynamic tab category count calculations in GlobalSearchModal');
});

test('Bug Fix 3: GlobalSearchModal resets selectedIndex on tab change', (t) => {
  const content = readFile('components/GlobalSearchModal.tsx');
  assert.ok(content.includes('handleTabChange'), 'Modal must implement handleTabChange handler');
  assert.ok(content.includes('setSelectedIndex(0)'), 'Tab change must reset selectedIndex to 0 to prevent out-of-bounds selection');
  t.diagnostic('Verified selectedIndex bounds protection on tab change');
});

test('Bug Fix 4: ThreatDetailModal resolves AI-DSPM capabilities', (t) => {
  const content = readFile('components/ThreatDetailModal.tsx');
  assert.ok(content.includes('GENAI_DSPM_CAPABILITIES'), 'ThreatDetailModal must import GENAI_DSPM_CAPABILITIES');
  assert.ok(content.includes('GENAI_DSPM_CAPABILITIES.find'), 'ThreatDetailModal must search and resolve AI-DSPM entries');
  assert.ok(content.includes('AI Data Security Posture Management (AI-DSPM)'), 'ThreatDetailModal must provide framework title for AI-DSPM');
  t.diagnostic('Verified AI-DSPM capability resolution in ThreatDetailModal');
});

test('Bug Fix 5: ThreatDetailModal prevents reverse tabnabbing in window.open fallbacks', (t) => {
  const content = readFile('components/ThreatDetailModal.tsx');
  const windowOpenCalls = [...content.matchAll(/window\.open\((.*?)\)/g)];
  assert.ok(windowOpenCalls.length > 0, 'Found window.open calls in ThreatDetailModal');
  for (const call of windowOpenCalls) {
    assert.ok(
      call[1].includes("'noopener,noreferrer'") || call[1].includes('"noopener,noreferrer"'),
      `window.open call must include 'noopener,noreferrer': ${call[0]}`
    );
  }
  t.diagnostic('Verified reverse tabnabbing protection on external links');
});

test('Bug Fix 6: AuditChecklistView severity styling distinctly styles Low risk level', (t) => {
  const content = readFile('components/AuditChecklistView.tsx');
  assert.ok(content.includes('getRiskBadgeClass'), 'AuditChecklistView must implement getRiskBadgeClass helper');
  assert.ok(content.includes("case 'Low': return 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20'"), 'Low risk level must be styled in emerald green');
  assert.ok(content.includes("case 'Critical':"), 'Critical risk level must be handled');
  assert.ok(content.includes("case 'High':"), 'High risk level must be handled');
  assert.ok(content.includes("case 'Medium':"), 'Medium risk level must be handled');
  t.diagnostic('Verified distinct severity badge styling in AuditChecklistView');
});

test('Bug Fix 7: AuditChecklistView renders interactive framework navigation tags and has no dead state', (t) => {
  const content = readFile('components/AuditChecklistView.tsx');
  assert.ok(!content.includes('const [isCopied, setIsCopied]'), 'AuditChecklistView must not retain dead isCopied state');
  assert.ok(content.includes('test.owaspTop10Ref && ('), 'Must render owaspTop10Ref tag');
  assert.ok(content.includes('test.owaspMlTop10Ref && ('), 'Must render owaspMlTop10Ref tag');
  assert.ok(content.includes('test.owaspAgenticRef && ('), 'Must render owaspAgenticRef tag');
  assert.ok(content.includes('test.owaspSaifRef && ('), 'Must render owaspSaifRef tag');
  assert.ok(content.includes('test.owaspMcpTop10Ref && ('), 'Must render owaspMcpTop10Ref tag');
  assert.ok(content.includes('onClick={() => onNavigateToOwasp('), 'Framework tags must be clickable and invoke onNavigateToOwasp');
  t.diagnostic('Verified framework navigation tags in AuditChecklistView');
});

test('Bug Fix 8: TestList badge displays filteredTests.length / tests.length ratio', (t) => {
  const content = readFile('components/TestList.tsx');
  assert.ok(
    content.includes('{filteredTests.length}') && content.includes('{tests.length} TEST CASES'),
    'TestList badge must render ratio of filteredTests.length against total tests.length'
  );
  assert.ok(!content.includes('{sortedTests.length} / {filteredTests.length} TEST CASES'), 'TestList must not render sortedTests.length / filteredTests.length (N/N bug)');
  t.diagnostic('Verified test count ratio badge in TestList');
});

test('Bug Fix 9: IncidentsDirectoryView supports DSGAI framework filter', (t) => {
  const content = readFile('components/IncidentsDirectoryView.tsx');
  assert.ok(content.includes("'DSGAI'"), 'IncidentsDirectoryView frameworkFilter must support DSGAI');
  assert.ok(content.includes("'All', 'LLM', 'ML', 'ASI', 'AST', 'SAIF', 'MCP', 'DSGAI'"), 'IncidentsDirectoryView must render DSGAI filter pill');
  t.diagnostic('Verified DSGAI framework filter option in IncidentsDirectoryView');
});

test('Bug Fix 10: TestDetail preserves suggested tool metadata without hardcoded override', (t) => {
  const content = readFile('components/TestDetail.tsx');
  assert.ok(content.includes('const tool = getEnrichedTool(rawTool);'), 'TestDetail must pass rawTool directly to getEnrichedTool');
  assert.ok(!content.includes("cost: 'Free'"), 'TestDetail must not hardcode overriding tool properties');
  t.diagnostic('Verified suggested tool metadata preservation in TestDetail');
});

test('Bug Fix 11: SecureMcpGuideView persists Minimum Bar checklist to localStorage safely', (t) => {
  const content = readFile('components/SecureMcpGuideView.tsx');
  assert.ok(content.includes('SECURE_MCP_CHECKLIST_STORAGE_KEY'), 'SecureMcpGuideView must define storage key');
  assert.ok(content.includes('localStorage.getItem(SECURE_MCP_CHECKLIST_STORAGE_KEY)'), 'Must load from localStorage');
  assert.ok(content.includes('localStorage.setItem(SECURE_MCP_CHECKLIST_STORAGE_KEY'), 'Must save to localStorage');
  assert.ok(content.includes('localStorage.removeItem(SECURE_MCP_CHECKLIST_STORAGE_KEY)'), 'Reset button must remove key from localStorage');
  assert.ok(content.includes('__proto__') && content.includes('constructor'), 'Must protect against prototype pollution during deserialization');
  t.diagnostic('Verified SecureMcpGuide checklist persistence and security guards');
});

test('Bug Fix 12: ToolsDirectoryView search matches ecosystems, typical use cases, and key features', (t) => {
  const content = readFile('components/ToolsDirectoryView.tsx');
  assert.ok(content.includes('(tool.ecosystem || []).join(\' \')'), 'Search must index tool ecosystems');
  assert.ok(content.includes('tool.typicalUseCase'), 'Search must index typical use cases');
  assert.ok(content.includes('(tool.keyFeatures || []).join(\' \')'), 'Search must index key features');
  t.diagnostic('Verified full-text search indexing coverage in ToolsDirectoryView');
});

test('Bug Fix 13: IncidentsDirectoryView search matches repercussions, remediation, and lessons learned', (t) => {
  const content = readFile('components/IncidentsDirectoryView.tsx');
  assert.ok(content.includes('incident.repercussions'), 'Search must index legal and corporate repercussions');
  assert.ok(content.includes('incident.remediation'), 'Search must index technical remediation');
  assert.ok(content.includes('incident.lessonsLearned'), 'Search must index practitioner lessons learned');
  t.diagnostic('Verified full-text search indexing coverage in IncidentsDirectoryView');
});

test('Bug Fix 14: Dashboard Incident Radar mapped threat badge is interactive', (t) => {
  const content = readFile('components/Dashboard.tsx');
  assert.ok(content.includes('onNavigateToOwasp(incident.threatId'), 'Incident Radar threat badge must be clickable and navigate to threat');
  assert.ok(content.includes('Mapped to {incident.threatId}'), 'Must display Mapped to threat ID');
  t.diagnostic('Verified interactive threat deep-link in Dashboard Incident Radar');
});

test('Bug Fix 15: App.tsx prevents test ID pollution of owaspTargetId', (t) => {
  const content = readFile('App.tsx');
  assert.ok(content.includes("initialHashState.view !== 'detail' ? initialHashState.id : null"), 'Initial state must not set owaspTargetId from detail test routes');
  assert.ok(content.includes("setOwaspTargetId(parsed.view !== 'detail' ? parsed.id : null)"), 'Hash change handler must only set owaspTargetId for framework views');
  t.diagnostic('Verified state isolation of owaspTargetId in App.tsx');
});

test('Bug Fix 16: ThreatDetailModal implements mobile safe area padding and clean body overflow reset', (t) => {
  const code = readFile('components/ThreatDetailModal.tsx');
  assert.ok(code.includes('env(safe-area-inset-top'), 'ThreatDetailModal must account for safe-area-inset-top');
  assert.ok(code.includes('safe-area-inset-bottom'), 'ThreatDetailModal must include safe area bottom inset padding');
  assert.ok(code.includes("document.body.style.overflow = previousOverflow"), 'ThreatDetailModal cleanup must reset body overflow to previousOverflow');
  assert.ok(!code.includes("document.body.style.overflow = 'unset';"), 'ThreatDetailModal cleanup must not use non-standard unset string');
  t.diagnostic('Verified ThreatDetailModal safe area clearance and overflow cleanup');
});
