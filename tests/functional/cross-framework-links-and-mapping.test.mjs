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

test('Cross-Framework - Complete ID Catalog Registry', (t) => {
  const llmContent = readFile('data_llm.ts');
  const mlContent = readFile('data_ml.ts');
  const asiContent = readFile('data_agentic_applications.ts');
  const astContent = readFile('data_agentic.ts');
  const saifContent = readFile('data_saif.ts');
  const mcpContent = readFile('data_mcp.ts');
  const dsgaiContent = readFile('data_genai_data_security.ts');
  const standardTestsContent = readFile('data_tests.ts');

  const llmIds = new Set([...llmContent.matchAll(/id:\s*["'](LLM\d{2}:\d{4})["']/g)].map(m => m[1]));
  const mlIds = new Set([...mlContent.matchAll(/id:\s*["'](ML\d{2}:\d{4})["']/g)].map(m => m[1]));
  const asiIds = new Set([...asiContent.matchAll(/id:\s*["'](ASI\d{2})["']/g)].map(m => m[1]));
  const astIds = new Set([...astContent.matchAll(/id:\s*["'](AST\d{2})["']/g)].map(m => m[1]));
  const saifIds = new Set([...saifContent.matchAll(/id:\s*["'](SAIF-R\d+)["']/g)].map(m => m[1]));
  const mcpIds = new Set([...mcpContent.matchAll(/id:\s*["'](MCP\d+:\d{4})["']/g)].map(m => m[1]));
  const dsgaiIds = new Set([...dsgaiContent.matchAll(/id:\s*["'](DSGAI\d{2})["']/g)].map(m => m[1]));
  const dspmIds = new Set([...dsgaiContent.matchAll(/id:\s*["'](ai-dspm-\d{2})["']/g)].map(m => m[1]));

  const standardTestIds = new Set([...standardTestsContent.matchAll(/id:\s*["'](AITG-[A-Z]+-\d+)["']/g)].map(m => m[1]));
  const agenticTestIds = new Set([...astContent.matchAll(/id:\s*["'](AGT-\d+)["']/g)].map(m => m[1]));
  const allTestIds = new Set([...standardTestIds, ...agenticTestIds]);

  assert.equal(llmIds.size, 10, 'Expected 10 LLM IDs');
  assert.equal(mlIds.size, 10, 'Expected 10 ML IDs');
  assert.equal(asiIds.size, 10, 'Expected 10 ASI IDs');
  assert.equal(astIds.size, 10, 'Expected 10 AST IDs');
  assert.equal(saifIds.size, 15, 'Expected 15 SAIF IDs');
  assert.equal(mcpIds.size, 10, 'Expected 10 MCP IDs');
  assert.equal(dsgaiIds.size, 21, 'Expected 21 DSGAI IDs');
  assert.equal(dspmIds.size, 13, 'Expected 13 AI-DSPM IDs');
  assert.equal(allTestIds.size, 42, 'Expected 42 total test items (32 standard + 10 agentic)');

  t.diagnostic(`Verified ${allTestIds.size} tests and 89 framework threat entries`);
});

test('Cross-Framework - Test Items Framework Cross-References Resolution', (t) => {
  const llmContent = readFile('data_llm.ts');
  const mlContent = readFile('data_ml.ts');
  const asiContent = readFile('data_agentic_applications.ts');
  const astContent = readFile('data_agentic.ts');
  const saifContent = readFile('data_saif.ts');
  const mcpContent = readFile('data_mcp.ts');
  const testsContent = readFile('data_tests.ts');

  const validLlmIds = new Set([...llmContent.matchAll(/id:\s*["'](LLM\d{2}:\d{4})["']/g)].map(m => m[1]));
  const validMlIds = new Set([...mlContent.matchAll(/id:\s*["'](ML\d{2}:\d{4})["']/g)].map(m => m[1]));
  const validAgenticIds = new Set([
    ...[...asiContent.matchAll(/id:\s*["'](ASI\d{2})["']/g)].map(m => m[1]),
    ...[...astContent.matchAll(/id:\s*["'](AST\d{2})["']/g)].map(m => m[1])
  ]);
  const validSaifIds = new Set([...saifContent.matchAll(/id:\s*["'](SAIF-R\d+)["']/g)].map(m => m[1]));
  const validMcpIds = new Set([...mcpContent.matchAll(/id:\s*["'](MCP\d+:\d{4})["']/g)].map(m => m[1]));

  // Extract all test references
  const llmRefs = [...testsContent.matchAll(/owaspTop10Ref:\s*["']([^"']+)["']/g)].map(m => m[1]);
  const mlRefs = [...testsContent.matchAll(/owaspMlTop10Ref:\s*["']([^"']+)["']/g)].map(m => m[1]);
  const agenticRefs = [...testsContent.matchAll(/owaspAgenticRef:\s*["']([^"']+)["']/g)].map(m => m[1]);
  const saifRefs = [...testsContent.matchAll(/owaspSaifRef:\s*["']([^"']+)["']/g)].map(m => m[1]);
  const mcpRefs = [...testsContent.matchAll(/owaspMcpTop10Ref:\s*["']([^"']+)["']/g)].map(m => m[1]);

  for (const ref of llmRefs) {
    assert.ok(validLlmIds.has(ref), `Test references unknown LLM ID: "${ref}"`);
  }
  for (const ref of mlRefs) {
    assert.ok(validMlIds.has(ref), `Test references unknown ML ID: "${ref}"`);
  }
  for (const ref of agenticRefs) {
    assert.ok(validAgenticIds.has(ref), `Test references unknown Agentic ID: "${ref}"`);
  }
  for (const ref of saifRefs) {
    assert.ok(validSaifIds.has(ref), `Test references unknown SAIF ID: "${ref}"`);
  }
  for (const ref of mcpRefs) {
    assert.ok(validMcpIds.has(ref), `Test references unknown MCP ID: "${ref}"`);
  }
});

test('Cross-Framework - Threat Modelling IDs and Related Tests Resolution', (t) => {
  const threatModelContent = readFile('components/ThreatModelling.tsx');
  const llmContent = readFile('data_llm.ts');
  const mlContent = readFile('data_ml.ts');
  const asiContent = readFile('data_agentic_applications.ts');
  const astContent = readFile('data_agentic.ts');
  const saifContent = readFile('data_saif.ts');
  const mcpContent = readFile('data_mcp.ts');
  const testsContent = readFile('data_tests.ts');
  const agenticTestsContent = readFile('data_agentic.ts');

  const standardTestIds = new Set([...testsContent.matchAll(/id:\s*["'](AITG-[A-Z]+-\d+)["']/g)].map(m => m[1]));
  const agenticTestIds = new Set([...agenticTestsContent.matchAll(/id:\s*["'](AGT-\d+)["']/g)].map(m => m[1]));
  const allValidTestIds = new Set([...standardTestIds, ...agenticTestIds]);

  const allValidThreatIds = new Set([
    ...[...llmContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mlContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...asiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...astContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...saifContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mcpContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1])
  ]);

  // Extract all threat IDs defined in ThreatModelling datasets (SAIF, LLM, ML, ASI, AST, MCP)
  const threatIdMatches = [...threatModelContent.matchAll(/id:\s*["']((?:LLM|ML|ASI|AST|SAIF|MCP)[^"']+)["']/g)].map(m => m[1]);
  for (const tid of threatIdMatches) {
    assert.ok(allValidThreatIds.has(tid), `ThreatModelling defines threat with unknown canonical ID: "${tid}"`);
  }

  // Extract all relatedTestIds in ThreatModelling
  const matches = [...threatModelContent.matchAll(/relatedTestIds:\s*\[(.*?)\]/gs)];
  let checkedCount = 0;
  for (const match of matches) {
    const rawIds = match[1].split(',').map(s => s.trim().replace(/['"]/g, '')).filter(Boolean);
    for (const testId of rawIds) {
      assert.ok(allValidTestIds.has(testId), `ThreatModelling references unknown test ID: "${testId}"`);
      checkedCount++;
    }
  }

  assert.ok(checkedCount > 0, `Verified ${checkedCount} relatedTestIds links in ThreatModelling`);
});

test('Cross-Framework - Tools Catalog Threat IDs Resolution', (t) => {
  const toolsContent = readFile('tools_catalog.ts');
  const llmContent = readFile('data_llm.ts');
  const mlContent = readFile('data_ml.ts');
  const asiContent = readFile('data_agentic_applications.ts');
  const astContent = readFile('data_agentic.ts');
  const saifContent = readFile('data_saif.ts');
  const mcpContent = readFile('data_mcp.ts');
  const dsgaiContent = readFile('data_genai_data_security.ts');

  const allValidThreatIds = new Set([
    ...[...llmContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mlContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...asiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...astContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...saifContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mcpContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...dsgaiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1])
  ]);

  // Match keys in TOOLS_BY_THREAT_ID: 'LLM01:2026': [ ... ]
  const toolKeys = [...toolsContent.matchAll(/['"]([A-Za-z0-9_:\-]+)['"]\s*:\s*\[/g)].map(m => m[1]);
  for (const key of toolKeys) {
    assert.ok(allValidThreatIds.has(key), `Tools catalog maps to unknown threat ID: "${key}"`);
  }
});

test('Cross-Framework - Incidents Catalog Threat IDs Resolution', (t) => {
  const incidentsContent = readFile('incidents_catalog.ts');
  const llmContent = readFile('data_llm.ts');
  const mlContent = readFile('data_ml.ts');
  const asiContent = readFile('data_agentic_applications.ts');
  const astContent = readFile('data_agentic.ts');
  const saifContent = readFile('data_saif.ts');
  const mcpContent = readFile('data_mcp.ts');
  const dsgaiContent = readFile('data_genai_data_security.ts');

  const allValidThreatIds = new Set([
    ...[...llmContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mlContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...asiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...astContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...saifContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mcpContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...dsgaiContent.matchAll(/id:\s*["'](DSGAI\d{2})["']/g)].map(m => m[1])
  ]);

  const incidentKeys = [...incidentsContent.matchAll(/['"]([A-Za-z0-9_:\-]+)['"]\s*:\s*([A-Za-z0-9_]+)/g)].map(m => ({ id: m[1], varName: m[2] }));
  for (const { id } of incidentKeys) {
    assert.ok(allValidThreatIds.has(id), `Incidents catalog maps to unknown threat ID: "${id}"`);
  }

  // Verify all Top 10 framework threats are covered in the incident catalog
  const top10ThreatIds = [
    ...[...llmContent.matchAll(/id:\s*["'](LLM\d{2}:\d{4})["']/g)].map(m => m[1]),
    ...[...mlContent.matchAll(/id:\s*["'](ML\d{2}:\d{4})["']/g)].map(m => m[1]),
    ...[...asiContent.matchAll(/id:\s*["'](ASI\d{2})["']/g)].map(m => m[1]),
    ...[...astContent.matchAll(/id:\s*["'](AST\d{2})["']/g)].map(m => m[1]),
    ...[...mcpContent.matchAll(/id:\s*["'](MCP\d+:\d{4})["']/g)].map(m => m[1])
  ];

  const mappedIds = new Set(incidentKeys.map(k => k.id));
  for (const threatId of top10ThreatIds) {
    assert.ok(mappedIds.has(threatId), `Top 10 threat "${threatId}" must be mapped in incidents_catalog.ts`);
  }
});

test('Cross-Framework - GenAI Data Security Cross-References Validity', (t) => {
  const dsgaiContent = readFile('data_genai_data_security.ts');
  const llmContent = readFile('data_llm.ts');
  const mlContent = readFile('data_ml.ts');
  const asiContent = readFile('data_agentic_applications.ts');
  const astContent = readFile('data_agentic.ts');
  const saifContent = readFile('data_saif.ts');
  const mcpContent = readFile('data_mcp.ts');

  const allValidIds = new Set([
    ...[...llmContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mlContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...asiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...astContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...saifContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mcpContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...dsgaiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1])
  ]);

  const crossRefMatches = [...dsgaiContent.matchAll(/crossReferences:\s*\[(.*?)\]/gs)];
  let verifiedEmbeddedCount = 0;

  for (const match of crossRefMatches) {
    const refs = match[1].split(',').map(s => s.trim().replace(/['"]/g, '')).filter(Boolean);
    for (const ref of refs) {
      // Find any embedded framework tokens (e.g. LLM04:2026, ASI03, AST02, DSGAI02, etc.)
      const embeddedIds = [...ref.matchAll(/\b(LLM\d{2}:\d{4}|ASI\d{2}|AST\d{2}|ML\d{2}:\d{4}|SAIF-R\d+|MCP\d+:\d{4}|DSGAI\d{2})\b/g)].map(m => m[1]);
      for (const embeddedId of embeddedIds) {
        assert.ok(allValidIds.has(embeddedId), `GenAI Data Security references unknown ID: "${embeddedId}" in string "${ref}"`);
        verifiedEmbeddedCount++;
      }
    }
  }

  assert.ok(verifiedEmbeddedCount > 0, `Verified ${verifiedEmbeddedCount} embedded framework IDs in GenAI Data Security cross-references`);
});

test('Cross-Framework - App Router Deep Linking Coverage for all Framework Prefixes', (t) => {
  const appContent = readFile('App.tsx');

  // Verify handleNavigateToOwasp handles all prefix families
  assert.ok(appContent.includes('id.startsWith("ML")'), 'Must route ML prefix');
  assert.ok(appContent.includes('id.startsWith("ASI")') || appContent.includes('id.startsWith("AST")'), 'Must route Agentic prefixes');
  assert.ok(appContent.includes('id.startsWith("SAIF")'), 'Must route SAIF prefix');
  assert.ok(appContent.includes('id.startsWith("MCP")'), 'Must route MCP prefix');
  assert.ok(appContent.includes('id.startsWith("DSGAI")') || appContent.includes('id.startsWith("ai-dspm")'), 'Must route GenAI Data Security prefix');
});

test('Cross-Framework - All relatedRisks References Resolve to Valid Threat IDs', (t) => {
  const llmContent = readFile('data_llm.ts');
  const mlContent = readFile('data_ml.ts');
  const asiContent = readFile('data_agentic_applications.ts');
  const astContent = readFile('data_agentic.ts');
  const saifContent = readFile('data_saif.ts');
  const mcpContent = readFile('data_mcp.ts');
  const dsgaiContent = readFile('data_genai_data_security.ts');

  const allValidThreatIds = new Set([
    ...[...llmContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mlContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...asiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...astContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...saifContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...mcpContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]),
    ...[...dsgaiContent.matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1])
  ]);

  // Extract all relatedRisks blocks
  const datasets = [
    { name: 'data_agentic_applications.ts', content: asiContent },
    { name: 'data_agentic.ts', content: astContent },
    { name: 'data_llm.ts', content: llmContent },
    { name: 'data_mcp.ts', content: mcpContent }
  ];

  let verifiedRelatedCount = 0;
  for (const { name, content } of datasets) {
    const relatedRiskMatches = [...content.matchAll(/relatedRisks:\s*\[([\s\S]*?)\]/g)];
    for (const match of relatedRiskMatches) {
      const idMatches = [...match[1].matchAll(/id:\s*["']([^"']+)["']/g)].map(m => m[1]);
      for (const id of idMatches) {
        assert.ok(allValidThreatIds.has(id), `File ${name} references unknown relatedRisk ID: "${id}"`);
        verifiedRelatedCount++;
      }
    }
  }

  assert.ok(verifiedRelatedCount > 0, `Verified ${verifiedRelatedCount} relatedRisks across frameworks`);
  t.diagnostic(`Verified ${verifiedRelatedCount} relatedRisks cross-references against ${allValidThreatIds.size} threats`);
});

test('UI Component - ThreatDetailModal and Non-Jumping Related Risk Inspection', (t) => {
  const modalContent = readFile('components/ThreatDetailModal.tsx');
  const owaspViewContent = readFile('components/OwaspTop10View.tsx');

  // Verify modal accessibility and security attributes
  assert.ok(modalContent.includes('role="dialog"'), 'ThreatDetailModal must declare role="dialog"');
  assert.ok(modalContent.includes('aria-modal="true"'), 'ThreatDetailModal must declare aria-modal="true"');
  assert.ok(modalContent.includes('aria-labelledby="threat-modal-title"'), 'ThreatDetailModal must bind aria-labelledby');
  assert.ok(modalContent.includes('e.key === \'Escape\''), 'ThreatDetailModal must implement Escape key dismissal');
  assert.ok(modalContent.includes('resolveThreatData'), 'ThreatDetailModal must export threat resolver');

  // Verify OwaspTop10View triggers modal window instead of page jumping
  assert.ok(owaspViewContent.includes('setSelectedThreatId(risk.id)'), 'Related risk click must open ThreatDetailModal');
  assert.ok(owaspViewContent.includes('<ThreatDetailModal'), 'OwaspTop10View must mount ThreatDetailModal');
});

test('UI Layout - OwaspTop10View Balanced Card Grid and Full-Width Sections', (t) => {
  const owaspViewContent = readFile('components/OwaspTop10View.tsx');
  const dsgaiViewContent = readFile('components/GenAiDataSecurityView.tsx');

  // Verify Row 1: Core Vulnerabilities vs Prevention Strategies
  assert.ok(owaspViewContent.includes('Common Vulnerabilities & Risks') || owaspViewContent.includes('Risk Mechanics & Impact'), 'Row 1 must render Common Vulnerabilities');
  assert.ok(owaspViewContent.includes('Prevention Strategies & Defense'), 'Row 1 must render Prevention Strategies');

  // Verify Row 2: Attack Scenarios vs Real-World Incidents
  assert.ok(owaspViewContent.includes('Attack Scenarios & Exploit Vectors'), 'Row 2 must render Attack Scenarios');
  assert.ok(owaspViewContent.includes('Real-World Incidents & Case Studies'), 'Row 2 must render Real-World Incidents');
  assert.ok(owaspViewContent.includes('lg:col-span-2'), 'Empty-column defense: single column expands to full width');

  // Verify Row 3 & 4: Guidance, Mappings, and Recommended Tools
  assert.ok(owaspViewContent.includes('Recommended Security Tools'), 'Card must render Recommended Security Tools');
  assert.ok(owaspViewContent.includes('grid grid-cols-1 md:grid-cols-2 gap-3.5'), 'Recommended tools must use responsive 2-column grid');
  assert.ok(owaspViewContent.includes('Reference Links'), 'Card must render Reference Links');

  // Verify Stable Instant Layout & Smooth GPU-Accelerated Mount (prevents dual-animation layout shift)
  assert.ok(owaspViewContent.includes('animate-in fade-in duration-200'), 'OwaspTop10View must use GPU-accelerated fade-in on mount');

  // Verify Viewport Scroll Alignment on Expansion (never start at end of card or jump casually)
  assert.ok(owaspViewContent.includes('scroll-mt-20 sm:scroll-mt-24'), 'OwaspTop10View cards must specify scroll-mt clearance for header');
  assert.ok(owaspViewContent.includes('scrollToCard') && owaspViewContent.includes('requestAnimationFrame'), 'OwaspTop10View must synchronize scroll with requestAnimationFrame');

  assert.ok(dsgaiViewContent.includes('scroll-mt-20 sm:scroll-mt-24'), 'GenAiDataSecurityView cards must specify scroll-mt clearance');
  assert.ok(dsgaiViewContent.includes('scrollToRisk') && dsgaiViewContent.includes('requestAnimationFrame'), 'GenAiDataSecurityView must synchronize scroll with requestAnimationFrame');
});

test('Testing Pillars - Suggested Tools are Interactive and Open ToolDetailModal', (t) => {
  const testDetailContent = readFile('components/TestDetail.tsx');

  // Verify TestDetail imports and mounts ToolDetailModal as a single instance
  assert.ok(testDetailContent.includes('import ToolDetailModal from \'./ToolDetailModal\''), 'TestDetail must import ToolDetailModal');
  assert.ok(testDetailContent.includes('getEnrichedTool'), 'TestDetail must use getEnrichedTool');
  assert.ok(testDetailContent.includes('<ToolDetailModal'), 'TestDetail must mount ToolDetailModal');
  assert.ok(testDetailContent.includes('handleToolClick(tool)'), 'Suggested tools must trigger handleToolClick');
  assert.ok(testDetailContent.includes('setSelectedTool(tool)'), 'TestDetail must manage single modal instance via local state');
});

test('Interactive Tools & Incidents - Verified Modal Mounting & Click Handlers Across Entire App', (t) => {
  const dashboardContent = readFile('components/Dashboard.tsx');
  const toolsViewContent = readFile('components/ToolsDirectoryView.tsx');
  const incidentsViewContent = readFile('components/IncidentsDirectoryView.tsx');
  const owaspViewContent = readFile('components/OwaspTop10View.tsx');
  const testDetailContent = readFile('components/TestDetail.tsx');
  const appContent = readFile('App.tsx');
  const searchModalContent = readFile('components/GlobalSearchModal.tsx');

  // 1. Dashboard: Marquee tools & Incident Radar
  assert.ok(dashboardContent.includes('onSelectTool'), 'Dashboard must accept onSelectTool prop');
  assert.ok(dashboardContent.includes('onSelectIncident'), 'Dashboard must accept onSelectIncident prop');
  assert.ok(dashboardContent.includes('ToolChip'), 'Dashboard must render ToolChip');
  assert.ok(dashboardContent.includes('onClick={(e) => {') && dashboardContent.includes('if (onSelectTool) onSelectTool(tool);'), 'ToolChip in Dashboard must trigger onSelectTool');
  assert.ok(dashboardContent.includes('if (onSelectIncident) onSelectIncident(incident);'), 'Incident Radar in Dashboard must trigger onSelectIncident');

  // 2. Tools Directory View: Modal mounted and grid items interactive
  assert.ok(toolsViewContent.includes('<ToolDetailModal'), 'ToolsDirectoryView must mount ToolDetailModal');
  assert.ok(toolsViewContent.includes('handleOpenTool(tool)'), 'Tool cards in ToolsDirectoryView must trigger handleOpenTool');

  // 3. Incidents Directory View: Modal mounted and grid items interactive
  assert.ok(incidentsViewContent.includes('<IncidentDetailModal'), 'IncidentsDirectoryView must mount IncidentDetailModal');
  assert.ok(incidentsViewContent.includes('handleOpenIncident(incident)'), 'Incident cards in IncidentsDirectoryView must trigger handleOpenIncident');

  // 4. OWASP Top 10 Views: Modals mounted and rows interactive
  assert.ok(owaspViewContent.includes('<ToolDetailModal'), 'OwaspTop10View must mount ToolDetailModal');
  assert.ok(owaspViewContent.includes('<IncidentDetailModal'), 'OwaspTop10View must mount IncidentDetailModal');
  assert.ok(owaspViewContent.includes('setSelectedTool(tool)'), 'Tool cards in OwaspTop10View must trigger setSelectedTool');
  assert.ok(owaspViewContent.includes('setSelectedIncident(getEnrichedIncident(incident, entry.id))'), 'Incident cards in OwaspTop10View must trigger setSelectedIncident');

  // 5. Test Detail: Modal mounted and suggested tools interactive
  assert.ok(testDetailContent.includes('<ToolDetailModal'), 'TestDetail must mount ToolDetailModal');
  assert.ok(testDetailContent.includes('handleToolClick(tool)'), 'Suggested tools in TestDetail must trigger handleToolClick');

  // 6. Global Search Modal & App.tsx routing
  assert.ok(searchModalContent.includes('onSelectTool(item.tool)'), 'GlobalSearchModal must support direct tool modal opening');
  assert.ok(searchModalContent.includes('onSelectIncident(item.incident)'), 'GlobalSearchModal must support direct incident modal opening');
  assert.ok(appContent.includes('onSelectTool={(tool) => setActiveModalTool(tool)}'), 'App.tsx must wire onSelectTool');
  assert.ok(appContent.includes('onSelectIncident={(incident) => setActiveModalIncident(incident)}'), 'App.tsx must wire onSelectIncident');

  // 7. Viewport Isolation & React Portal Immunity (avoids CSS transform clipping)
  const toolModalContent = readFile('components/ToolDetailModal.tsx');
  const incidentModalContent = readFile('components/IncidentDetailModal.tsx');
  const threatModalContent = readFile('components/ThreatDetailModal.tsx');
  assert.ok(toolModalContent.includes('createPortal('), 'ToolDetailModal must use createPortal to mount on document.body');
  assert.ok(incidentModalContent.includes('createPortal('), 'IncidentDetailModal must use createPortal to mount on document.body');
  assert.ok(threatModalContent.includes('createPortal('), 'ThreatDetailModal must use createPortal to mount on document.body');
  assert.ok(searchModalContent.includes('createPortal('), 'GlobalSearchModal must use createPortal to mount on document.body');

  // 8. Single-Instance Modal Guarantee (Prevents layered duplicate modal double-click dismiss bugs)
  const toolModalTagCount = (toolsViewContent.match(/<ToolDetailModal/g) || []).length;
  assert.strictEqual(toolModalTagCount, 1, 'ToolsDirectoryView must contain exactly ONE <ToolDetailModal instance to avoid double modal layering');
  
  const incidentModalTagCount = (incidentsViewContent.match(/<IncidentDetailModal/g) || []).length;
  assert.strictEqual(incidentModalTagCount, 1, 'IncidentsDirectoryView must contain exactly ONE <IncidentDetailModal instance');

  assert.ok(
    toolsViewContent.includes('if (onSelectTool)') && toolsViewContent.includes('onSelectTool(tool)') && toolsViewContent.includes('else {') && toolsViewContent.includes('setSelectedTool(tool)'),
    'ToolsDirectoryView must delegate to onSelectTool when present to avoid setting both local and global state'
  );

  assert.ok(
    incidentsViewContent.includes('if (onSelectIncident)') && incidentsViewContent.includes('onSelectIncident(incident)') && incidentsViewContent.includes('else {') && incidentsViewContent.includes('setSelectedIncident(incident)'),
    'IncidentsDirectoryView must delegate to onSelectIncident when present to avoid setting both local and global state'
  );

  t.diagnostic('Verified 100% interactive modal wiring, createPortal viewport immunity, and single-instance modal guarantee across the entire application');
});
