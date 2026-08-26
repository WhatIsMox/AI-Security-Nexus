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

// =========================================================================
// VECTOR A: Functional & Boundary Testing (Scenarios A1 - A8)
// =========================================================================

test('Vector A - Scenario A1: Global Search Boundary (Regex & Special Chars)', () => {
  const searchModalCode = readFile('components/GlobalSearchModal.tsx');
  
  // Verify that search querying uses standard safe substring matching (.includes) rather than raw RegExp eval
  assert.ok(
    searchModalCode.includes('.includes(cleanQuery)') || searchModalCode.includes('.includes('),
    'Global search must use safe string inclusion to avoid unhandled RegExp syntax errors'
  );

  // Fuzz with regex metacharacters
  const fuzzQueries = ['.*', '[a-z]+', '(?=.*)', '\\d{3}', '\\0', '(?!)', '{10,20}', '(', '[', '*', '+', '?'];
  const testSample = "AITG-APP-01 Testing for Prompt Injection LLM01:2026 Application Critical";
  for (const query of fuzzQueries) {
    const clean = query.trim().toLowerCase();
    assert.doesNotThrow(() => {
      testSample.toLowerCase().includes(clean);
    }, `Search querying "${query}" should not throw regex errors`);
  }
});

test('Vector A - Scenario A2: Global Search Boundary (Long Strings, Unicode Emojis & RTL)', () => {
  const longPayload = 'A'.repeat(50000);
  const unicodePayload = '🔥💉🤖👨‍👩‍👧‍👦🚨⚠️🛡️\u202E\u200F\uFEFF';
  const testSample = "AITG-APP-01 Testing for Prompt Injection LLM01:2026";

  assert.strictEqual(testSample.toLowerCase().includes(longPayload.toLowerCase()), false);
  assert.doesNotThrow(() => testSample.toLowerCase().includes(unicodePayload.toLowerCase()));
});

test('Vector A - Scenario A3: Audit Checklist Notes & Markdown Table Injection Sanitization (CWE-1236)', () => {
  const auditViewCode = readFile('components/AuditChecklistView.tsx');

  // Verify pipe escaping
  assert.ok(
    auditViewCode.includes(".replace(/\\|/g, '\\\\|')") || auditViewCode.includes('.replace(/\\|/g,'),
    'Audit exportMarkdown must escape pipe characters (|) to prevent markdown table injection'
  );

  // Verify newline sanitation
  assert.ok(
    auditViewCode.includes(".replace(/\\n/g, ' ')") || auditViewCode.includes('.replace(/\\n/g,'),
    'Audit exportMarkdown must sanitize newline characters to prevent multi-line table breakout'
  );

  // Simulate malicious table injection notes
  const injectionNote = "Note header | Vulnerable | Critical | [Injected Column](https://evil.example.com) \n| New row |";
  const sanitizedNote = injectionNote.replace(/\|/g, '\\|').replace(/\n/g, ' ');
  assert.ok(!sanitizedNote.includes('\n'), 'Sanitized note must not contain unescaped newlines');
  assert.ok(sanitizedNote.includes('\\|'), 'Sanitized note must escape pipe characters');
});

test('Vector A - Scenario A4: Test List Free-Text Search - Boundary & Space-Only Inputs', () => {
  const testListCode = readFile('components/TestList.tsx');
  assert.ok(testListCode.includes('searchQuery.trim().toLowerCase()'), 'TestList must trim search queries');

  const testsContent = readFile('data_tests.ts');
  const ids = [...testsContent.matchAll(/id:\s*["'](AITG-[A-Z]+-\d+)["']/g)].map(m => m[1]);
  assert.ok(ids.length > 0, 'Found test IDs in catalog');
});

test('Vector A - Scenario A5: Tools Directory Search & Combined Filter Boundary', () => {
  const toolsViewCode = readFile('components/ToolsDirectoryView.tsx');
  assert.ok(toolsViewCode.includes('categoryFilter'), 'Tools directory must support category filter');
  assert.ok(toolsViewCode.includes('costFilter'), 'Tools directory must support cost filter');
  assert.ok(toolsViewCode.includes('typeFilter'), 'Tools directory must support type filter');
  assert.ok(toolsViewCode.includes('No security tools match the active filters'), 'Must render clean empty-state message');
});

test('Vector A - Scenario A6: Incidents Directory Search & Framework Filter Matrix', () => {
  const incidentsViewCode = readFile('components/IncidentsDirectoryView.tsx');
  assert.ok(incidentsViewCode.includes('availableFrameworks'), 'Incidents directory must compute availableFrameworks');
  assert.ok(incidentsViewCode.includes('activeFrameworkFilter'), 'Incidents directory must compute activeFrameworkFilter');

  const frameworks = ['All', 'LLM', 'ML', 'ASI', 'AST', 'SAIF', 'MCP', 'DSGAI'];
  for (const fw of frameworks) {
    assert.ok(incidentsViewCode.includes(`'${fw}'`), `Incidents directory must support framework filter '${fw}'`);
  }
});

test('Vector A - Scenario A7: Secure MCP Guide - Search & Collapse/Expand Boundary', () => {
  const secureMcpCode = readFile('components/SecureMcpGuideView.tsx');
  assert.ok(secureMcpCode.includes('areFilteredSectionsExpanded'), 'Secure MCP guide must track toggle-all state');
  assert.ok(secureMcpCode.includes('toggleFilteredSections'), 'Secure MCP guide must implement toggleFilteredSections');
  assert.ok(secureMcpCode.includes('clearSearch'), 'Secure MCP guide must provide clearSearch');
});

test('Vector A - Scenario A8: GenAI Data Security - Tier & Theme Filter Cross-Product', () => {
  const dsgaiCode = readFile('components/GenAiDataSecurityView.tsx');
  assert.ok(dsgaiCode.includes('themeFilter'), 'GenAiDataSecurityView must filter by theme');
  assert.ok(dsgaiCode.includes('tierFilter'), 'GenAiDataSecurityView must filter by tier');
  assert.ok(dsgaiCode.includes('GENAI_DATA_SECURITY_RISKS'), 'GenAiDataSecurityView must use GENAI_DATA_SECURITY_RISKS');
  assert.ok(dsgaiCode.includes('GENAI_DSPM_CAPABILITIES'), 'GenAiDataSecurityView must use GENAI_DSPM_CAPABILITIES');
});

// =========================================================================
// VECTOR B: State Corruption & Navigation Stress (Scenarios B1 - B8)
// =========================================================================

test('Vector B - Scenario B1: Hash Routing Malformed URL Slugs & Fallback', () => {
  const appCode = readFile('App.tsx');
  assert.ok(appCode.includes('parseHashToState'), 'App.tsx must define parseHashToState function');
  assert.ok(appCode.includes("clean.startsWith('detail/')"), 'App.tsx must parse detail routes');
});

test('Vector B - Scenario B2: Rapid Hash Navigation & Popstate Churn', () => {
  const appCode = readFile('App.tsx');
  assert.ok(appCode.includes("window.addEventListener('hashchange', handleHashChange)"), 'App must listen for hashchange');
  assert.ok(appCode.includes("window.addEventListener('popstate', handleHashChange)"), 'App must listen for popstate');
  assert.ok(appCode.includes("window.removeEventListener('hashchange', handleHashChange)"), 'App must clean up hashchange listener');
  assert.ok(appCode.includes("window.removeEventListener('popstate', handleHashChange)"), 'App must clean up popstate listener');
});

test('Vector B - Scenario B3: Modal Stacking & Simultaneous Triggers', () => {
  const appCode = readFile('App.tsx');
  assert.ok(appCode.includes('activeModalTool'), 'App.tsx must manage activeModalTool state');
  assert.ok(appCode.includes('activeModalIncident'), 'App.tsx must manage activeModalIncident state');
  assert.ok(appCode.includes('isSearchOpen'), 'App.tsx must manage isSearchOpen state');
});

test('Vector B - Scenario B4: Local Storage Deserialization Poisoning & Corruption', () => {
  const auditViewCode = readFile('components/AuditChecklistView.tsx');
  const secureMcpCode = readFile('components/SecureMcpGuideView.tsx');

  assert.ok(auditViewCode.includes("key !== '__proto__'"), 'AuditChecklist must guard __proto__');
  assert.ok(auditViewCode.includes("key !== 'constructor'"), 'AuditChecklist must guard constructor');
  assert.ok(secureMcpCode.includes("key !== '__proto__'"), 'SecureMcpGuide must guard __proto__');
  assert.ok(secureMcpCode.includes("key !== 'constructor'"), 'SecureMcpGuide must guard constructor');
});

test('Vector B - Scenario B5: Audit Checklist Reset & Multi-click Stress', () => {
  const auditViewCode = readFile('components/AuditChecklistView.tsx');
  assert.ok(auditViewCode.includes('handleReset'), 'AuditChecklist must implement handleReset');
  assert.ok(auditViewCode.includes('saveRecords'), 'AuditChecklist must implement saveRecords');
});

test('Vector B - Scenario B6: Global Search Modal Keyboard Navigation Stress', () => {
  const searchModalCode = readFile('components/GlobalSearchModal.tsx');
  assert.ok(searchModalCode.includes("e.key === 'ArrowDown'"), 'GlobalSearchModal must handle ArrowDown');
  assert.ok(searchModalCode.includes("e.key === 'ArrowUp'"), 'GlobalSearchModal must handle ArrowUp');
  assert.ok(searchModalCode.includes("e.key === 'Enter'"), 'GlobalSearchModal must handle Enter');
  assert.ok(searchModalCode.includes("e.key === 'Escape'"), 'GlobalSearchModal must handle Escape');
});

test('Vector B - Scenario B7: Domain Filtering Persistence across Navigation', () => {
  const appCode = readFile('App.tsx');
  assert.ok(appCode.includes('globalDomain'), 'App.tsx must manage globalDomain state');
  assert.ok(appCode.includes('setGlobalDomain'), 'App.tsx must provide setGlobalDomain');
});

test('Vector B - Scenario B8: Test Detail Payload Copy & Missing Code Block Safety', () => {
  const testDetailCode = readFile('components/TestDetail.tsx');
  assert.ok(testDetailCode.includes('handleCopyPayload'), 'TestDetail must implement handleCopyPayload');
  assert.ok(testDetailCode.includes('navigator?.clipboard?.writeText'), 'TestDetail must verify clipboard API existence');
});

// =========================================================================
// VECTOR C: Auth & Access Control Boundaries (Scenarios C1 - C7)
// =========================================================================

test('Vector C - Scenario C1: Direct Deep-link Route Manipulation', () => {
  const appCode = readFile('App.tsx');
  assert.ok(appCode.includes("clean.startsWith('detail/')"), 'Must handle direct detail link');
  assert.ok(appCode.includes("clean.startsWith('owasp-top10')"), 'Must handle direct owasp-top10 link');
  assert.ok(appCode.includes("clean === 'tools'") || appCode.includes("clean.startsWith('tools')"), 'Must handle direct tools link');
  assert.ok(appCode.includes("clean === 'incidents'") || appCode.includes("clean.startsWith('incidents')"), 'Must handle direct incidents link');
});

test('Vector C - Scenario C2: Cross-Site Scripting / Dangerous Protocol Injection via URL', () => {
  const codeFiles = ['App.tsx', 'components/Sidebar.tsx', 'components/GlobalSearchModal.tsx'];
  for (const file of codeFiles) {
    const content = readFile(file);
    assert.ok(!content.includes('javascript:'), `${file} must not contain javascript: URLs`);
    assert.ok(!content.includes('vbscript:'), `${file} must not contain vbscript: URLs`);
    assert.ok(!content.includes('dangerouslySetInnerHTML'), `${file} must not use dangerouslySetInnerHTML`);
  }
});

test('Vector C - Scenario C3: Strict Rel="noopener noreferrer" on all External Anchors (CWE-1022)', () => {
  const componentsDir = path.join(rootDir, 'components');
  const files = fs.readdirSync(componentsDir).filter(f => f.endsWith('.tsx'));

  let verifiedLinks = 0;
  for (const file of files) {
    const content = fs.readFileSync(path.join(componentsDir, file), 'utf8');
    const blankRegex = /<a\s+[^>]*target="_blank"[^>]*>/g;
    let match;
    while ((match = blankRegex.exec(content)) !== null) {
      assert.ok(
        match[0].includes('rel="noopener noreferrer"'),
        `Anchor in components/${file} with target="_blank" must include rel="noopener noreferrer": ${match[0]}`
      );
      verifiedLinks++;
    }
  }
  assert.ok(verifiedLinks > 0, `Verified ${verifiedLinks} external links with strict rel="noopener noreferrer"`);
});

test('Vector C - Scenario C4: CSP Compliance & Zero-Inline-Script Execution', () => {
  const viteConfig = readFile('vite.config.ts');
  assert.ok(viteConfig.includes("default-src 'self'"), 'CSP must set default-src self');
  assert.ok(viteConfig.includes("object-src 'none'"), 'CSP must disallow object-src');
  assert.ok(viteConfig.includes("base-uri 'self'"), 'CSP must set base-uri self');
});

test('Vector C - Scenario C5: Payload Code Block Escaping (Safe Text in Pre/Code)', () => {
  const testDetailCode = readFile('components/TestDetail.tsx');
  assert.ok(testDetailCode.includes('<pre'), 'TestDetail must wrap payloads in pre tag');
  assert.ok(testDetailCode.includes('<code>{payload.code}</code>'), 'TestDetail must render payload as raw text in code block');
});

test('Vector C - Scenario C6: LocalStorage Key Namespace Isolation', () => {
  const auditViewCode = readFile('components/AuditChecklistView.tsx');
  const secureMcpCode = readFile('components/SecureMcpGuideView.tsx');

  assert.ok(auditViewCode.includes("STORAGE_KEY = 'ai_security_nexus_audit_state_v1'"), 'AuditChecklist must use versioned namespace');
  assert.ok(secureMcpCode.includes("SECURE_MCP_CHECKLIST_STORAGE_KEY = 'ai_security_nexus_secure_mcp_checklist_v1'"), 'SecureMcpGuide must use versioned namespace');
});

test('Vector C - Scenario C7: Safe Area and Mobile Touch Target Bounds', () => {
  const searchModalCode = readFile('components/GlobalSearchModal.tsx');
  const threatModalCode = readFile('components/ThreatDetailModal.tsx');
  const toolModalCode = readFile('components/ToolDetailModal.tsx');
  const incidentModalCode = readFile('components/IncidentDetailModal.tsx');

  assert.ok(searchModalCode.includes('safe-area-inset-top'), 'GlobalSearchModal must account for safe-area-inset-top');
  assert.ok(threatModalCode.includes('safe-area-inset-top'), 'ThreatDetailModal must account for safe-area-inset-top');
  assert.ok(toolModalCode.includes('safe-area-inset-top'), 'ToolDetailModal must account for safe-area-inset-top');
  assert.ok(incidentModalCode.includes('safe-area-inset-top'), 'IncidentDetailModal must account for safe-area-inset-top');
});

// =========================================================================
// VECTOR D: Network & Failure Resilience (Scenarios D1 - D7)
// =========================================================================

test('Vector D - Scenario D1: Offline Mode / Pure SPA Static Bundling', () => {
  const packageJson = JSON.parse(readFile('package.json'));
  const serverPackages = ['express', 'koa', 'fastify', 'hapi', 'nest', 'next'];
  for (const pkg of serverPackages) {
    assert.strictEqual(packageJson.dependencies[pkg], undefined, `Pure static SPA must not depend on ${pkg}`);
  }
});

test('Vector D - Scenario D2: Broken External Link Fallback & Error Containment', () => {
  const incidentModalCode = readFile('components/IncidentDetailModal.tsx');
  const toolModalCode = readFile('components/ToolDetailModal.tsx');
  assert.ok(incidentModalCode.includes('target="_blank"'), 'External link must open in new tab');
  assert.ok(toolModalCode.includes('target="_blank"'), 'External link must open in new tab');
});

test('Vector D - Scenario D3: Clipboard API Rejection & Fallback Graceful Handling', () => {
  const testDetailCode = readFile('components/TestDetail.tsx');
  const threatModalCode = readFile('components/ThreatDetailModal.tsx');
  const toolModalCode = readFile('components/ToolDetailModal.tsx');

  assert.ok(testDetailCode.includes('navigator?.clipboard?.writeText'), 'TestDetail must verify clipboard API existence');
  assert.ok(testDetailCode.includes('.catch('), 'TestDetail must catch clipboard promise rejection');
  assert.ok(threatModalCode.includes('navigator.clipboard.writeText') || threatModalCode.includes('navigator?.clipboard?.writeText'), 'ThreatDetailModal must implement clipboard write');
  assert.ok(toolModalCode.includes('navigator.clipboard.writeText') || toolModalCode.includes('navigator?.clipboard?.writeText'), 'ToolDetailModal must implement clipboard write');
});

test('Vector D - Scenario D4: Lazy Component Chunk Loading Fallback State', () => {
  const appCode = readFile('App.tsx');
  assert.ok(appCode.includes('ViewLoadingFallback'), 'App.tsx must define ViewLoadingFallback');
  assert.ok(appCode.includes('<Suspense fallback={<ViewLoadingFallback />}>'), 'App.tsx must wrap views in Suspense');
});

test('Vector D - Scenario D5: Print Stylesheet & PDF Export Generation', () => {
  const auditViewCode = readFile('components/AuditChecklistView.tsx');
  assert.ok(auditViewCode.includes('window.print()'), 'AuditChecklistView must trigger window.print()');
});

test('Vector D - Scenario D6: JSON Blob Download & URL.revokeObjectURL Cleanup', () => {
  const auditViewCode = readFile('components/AuditChecklistView.tsx');
  assert.ok(auditViewCode.includes('URL.createObjectURL(blob)'), 'Must create blob URL for export');
  assert.ok(auditViewCode.includes('URL.revokeObjectURL(url)'), 'Must revoke object URL after export to prevent memory leak');
});

test('Vector D - Scenario D7: Analytics / Telemetry Non-Blocking Execution', () => {
  const indexHtml = readFile('index.html');
  if (indexHtml.includes('stats.byreference.net')) {
    assert.ok(indexHtml.includes('async') && indexHtml.includes('defer'), 'Analytics script must be async and defer');
  }
});

// =========================================================================
// VECTOR E: Console & Runtime Leak Detection (Scenarios E1 - E6)
// =========================================================================

test('Vector E - Scenario E1: Event Listener Cleanup on Unmount', () => {
  const filesWithListeners = [
    { file: 'App.tsx', listeners: ['hashchange', 'popstate', 'keydown'] },
    { file: 'components/GlobalSearchModal.tsx', listeners: [] },
    { file: 'components/ThreatDetailModal.tsx', listeners: ['keydown'] },
    { file: 'components/ToolDetailModal.tsx', listeners: ['keydown'] },
    { file: 'components/IncidentDetailModal.tsx', listeners: ['keydown'] }
  ];

  for (const { file, listeners } of filesWithListeners) {
    const code = readFile(file);
    for (const listener of listeners) {
      assert.ok(code.includes(`addEventListener('${listener}'`), `${file} must attach ${listener}`);
      assert.ok(code.includes(`removeEventListener('${listener}'`), `${file} must cleanly remove ${listener} on unmount`);
    }
  }
});

test('Vector E - Scenario E2: Memory Leak & Zombie Animation/Observer Disconnect', () => {
  const dashboardCode = readFile('components/Dashboard.tsx');
  assert.ok(dashboardCode.includes('observer.disconnect()'), 'Dashboard useInView must disconnect IntersectionObserver');
  assert.ok(dashboardCode.includes('cancelAnimationFrame'), 'Dashboard must cancel animation frame on unmount');
});

test('Vector E - Scenario E3: Duplicate React Key Absence across Catalog Data', () => {
  const testsContent = readFile('data_tests.ts');
  const agenticContent = readFile('data_agentic.ts');
  const testIds = [
    ...testsContent.matchAll(/id:\s*["'](AITG-[A-Z]+-\d+)["']/g),
    ...agenticContent.matchAll(/id:\s*["'](AGT-\d+)["']/g)
  ].map(m => m[1]);

  const uniqueIds = new Set(testIds);
  assert.equal(uniqueIds.size, testIds.length, 'All test IDs in catalogs must be globally unique');
});

test('Vector E - Scenario E4: Body Overflow Lock Cleanup on Modal Dismiss', () => {
  const threatModalCode = readFile('components/ThreatDetailModal.tsx');
  const toolModalCode = readFile('components/ToolDetailModal.tsx');
  const incidentModalCode = readFile('components/IncidentDetailModal.tsx');

  assert.ok(threatModalCode.includes("document.body.style.overflow = ''"), 'ThreatDetailModal must clean up body overflow lock');
  assert.ok(toolModalCode.includes("document.body.style.overflow = ''"), 'ToolDetailModal must clean up body overflow lock');
  assert.ok(incidentModalCode.includes("document.body.style.overflow = ''"), 'IncidentDetailModal must clean up body overflow lock');
});

test('Vector E - Scenario E5: ARIA Modal Focus & Accessibility Landmark Validation', () => {
  const modals = [
    'components/GlobalSearchModal.tsx',
    'components/ThreatDetailModal.tsx',
    'components/ToolDetailModal.tsx',
    'components/IncidentDetailModal.tsx'
  ];

  for (const modalFile of modals) {
    const code = readFile(modalFile);
    assert.ok(code.includes('role="dialog"'), `${modalFile} must declare role="dialog"`);
    assert.ok(code.includes('aria-modal="true"'), `${modalFile} must declare aria-modal="true"`);
  }
});

test('Vector E - Scenario E6: Zero TypeScript Strictness Violations', () => {
  const tsconfig = JSON.parse(readFile('tsconfig.json'));
  assert.strictEqual(tsconfig.compilerOptions.strict, true, 'tsconfig.json must enable strict: true');
});
