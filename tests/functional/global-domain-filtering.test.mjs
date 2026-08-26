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

test('Global Domain Filtering - Type Definition', (t) => {
  const content = readFile('types.ts');
  assert.ok(content.includes('export type GlobalDomain'), 'types.ts must define GlobalDomain type');
  assert.ok(content.includes("'ALL'"), 'GlobalDomain must include ALL');
  assert.ok(content.includes("'LLM'"), 'GlobalDomain must include LLM');
  assert.ok(content.includes("'ML'"), 'GlobalDomain must include ML');
  assert.ok(content.includes("'AGENT'"), 'GlobalDomain must include AGENT');
  assert.ok(content.includes("'MCP'"), 'GlobalDomain must include MCP');
});

test('Global Domain Filtering - State & Prop Drilling in App.tsx', (t) => {
  const content = readFile('App.tsx');
  
  // State declaration
  assert.ok(
    content.includes('const [globalDomain, setGlobalDomain] = useState<GlobalDomain>(\'ALL\');') ||
    content.includes('const [globalDomain, setGlobalDomain] = useState<GlobalDomain>("ALL");'), 
    'App.tsx must declare globalDomain state'
  );

  // Prop drilling
  const propCount = (content.match(/globalDomain={globalDomain}/g) || []).length;
  // Sidebar + Dashboard + ThreatModelling + AuditChecklist + ToolsDirectory + IncidentsDirectory = 6
  assert.ok(propCount >= 6, 'App.tsx must pass globalDomain prop to at least 6 core child components');
  assert.ok(content.includes('onSelectDomain={setGlobalDomain}'), 'App.tsx must pass setGlobalDomain to Sidebar');
  
  // Data array filtering
  assert.ok(content.includes('if (globalDomain !== \'ALL\')'), 'App.tsx must enforce early return or branching for ALL domain in data processing');
});

test('Global Domain Filtering - Sidebar UI', (t) => {
  const content = readFile('components/Sidebar.tsx');
  
  assert.ok(content.includes('globalDomain: GlobalDomain'), 'SidebarProps must include globalDomain');
  assert.ok(content.includes('onSelectDomain: (domain: GlobalDomain) => void'), 'SidebarProps must include onSelectDomain');
  assert.ok(content.includes('<select'), 'Sidebar must render a select dropdown for domain filtering');
  assert.ok(content.includes('onChange={(e) => onSelectDomain'), 'Sidebar select must trigger onSelectDomain on change');
});

test('Global Domain Filtering - View Component Adherence', (t) => {
  const dashboard = readFile('components/Dashboard.tsx');
  const tools = readFile('components/ToolsDirectoryView.tsx');
  const incidents = readFile('components/IncidentsDirectoryView.tsx');
  const threatModel = readFile('components/ThreatModelling.tsx');
  const audit = readFile('components/AuditChecklistView.tsx');

  const components = [
    { name: 'Dashboard', content: dashboard },
    { name: 'ToolsDirectoryView', content: tools },
    { name: 'IncidentsDirectoryView', content: incidents },
    { name: 'ThreatModelling', content: threatModel },
    { name: 'AuditChecklistView', content: audit }
  ];

  components.forEach(({ name, content }) => {
    assert.ok(
      content.includes('globalDomain: GlobalDomain') || content.includes('globalDomain?: GlobalDomain'), 
      `${name} Props must include globalDomain definition`
    );
    assert.ok(content.includes('const '), `${name} must compute derived state`);
    assert.ok(content.includes('globalDomain === \'LLM\'') || content.includes('globalDomain === "LLM"'), `${name} must filter by LLM domain`);
    assert.ok(content.includes('globalDomain === \'ML\'') || content.includes('globalDomain === "ML"'), `${name} must filter by ML domain`);
    assert.ok(content.includes('globalDomain === \'AGENT\'') || content.includes('globalDomain === "AGENT"'), `${name} must filter by AGENT domain`);
    assert.ok(content.includes('globalDomain === \'MCP\'') || content.includes('globalDomain === "MCP"'), `${name} must filter by MCP domain`);
  });
});
