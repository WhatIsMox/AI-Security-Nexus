/**
 * Functional Tests — Sidebar Navigation Structure & ARIA Conformance
 *
 * The Sidebar is the primary navigation spine of the application, yet has zero
 * dedicated tests. These cover: AppView type completeness, ActivePillarKey coverage,
 * navigation item rendering for all frameworks, ARIA semantics, and brand integration.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../..');

function readFile(relativePath) {
  let fullPath = path.join(rootDir, relativePath);
  if (!fs.existsSync(fullPath)) {
    if (fs.existsSync(path.join(rootDir, 'src/data', relativePath))) {
      fullPath = path.join(rootDir, 'src/data', relativePath);
    } else if (fs.existsSync(path.join(rootDir, 'src/components', relativePath))) {
      fullPath = path.join(rootDir, 'src/components', relativePath);
    } else if (fs.existsSync(path.join(rootDir, 'src', relativePath))) {
      fullPath = path.join(rootDir, 'src', relativePath);
    }
  }
  return fs.readFileSync(fullPath, 'utf8');
}

// ─── 1. AppView Type Completeness ────────────────────────────────────────────

test('Sidebar - AppView type union includes all 14 recognized view identifiers', (t) => {
  const sidebarContent = readFile('components/Sidebar.tsx');

  const requiredViews = [
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
    'incidents',
  ];

  for (const view of requiredViews) {
    assert.ok(sidebarContent.includes(`'${view}'`), `Sidebar AppView type must include '${view}'`);
  }

  t.diagnostic(`Verified all ${requiredViews.length} view identifiers in AppView type`);
});

test('Sidebar - ActivePillarKey type includes all 4 Pillars plus framework-specific keys', (t) => {
  const sidebarContent = readFile('components/Sidebar.tsx');

  const requiredPillarKeys = [
    'ALL',
    'TOP10',
    'MLTOP10',
    'AGENTTOP10',
    'SAIFTOP10',
    'MCPTOP10',
    'SECUREMCPGUIDE',
    'GENAIDATASECURITY',
  ];

  for (const key of requiredPillarKeys) {
    assert.ok(sidebarContent.includes(`'${key}'`), `Sidebar ActivePillarKey type must include '${key}'`);
  }

  // Must also import Pillar enum from types
  assert.ok(
    sidebarContent.includes("from '../types'") || sidebarContent.includes('from "../types"'),
    'Sidebar must import Pillar from types.ts'
  );
  assert.ok(sidebarContent.includes('Pillar'), 'Sidebar must reference Pillar enum for pillar keys');
});

// ─── 2. Navigation Items ──────────────────────────────────────────────────────

test('Sidebar - renders navigation items for all 4 pillar test categories', (t) => {
  const sidebarContent = readFile('components/Sidebar.tsx');

  // Standard pillar nav items
  assert.ok(sidebarContent.includes('Application Testing') || sidebarContent.includes('Pillar.APP'), 'Sidebar must render APP pillar item');
  assert.ok(sidebarContent.includes('Model Testing') || sidebarContent.includes('Pillar.MODEL'), 'Sidebar must render MODEL pillar item');
  assert.ok(sidebarContent.includes('Infrastructure') || sidebarContent.includes('Pillar.INFRA'), 'Sidebar must render INFRA pillar item');
  assert.ok(sidebarContent.includes('Data Testing') || sidebarContent.includes('Pillar.DATA'), 'Sidebar must render DATA pillar item');
});

test('Sidebar - renders navigation entries for all 7 framework views', (t) => {
  const sidebarContent = readFile('components/Sidebar.tsx');

  // Framework view entries (check for recognizable labels or routes)
  assert.ok(
    sidebarContent.includes('owasp-top10') || sidebarContent.includes('TOP10'),
    'Sidebar must render LLM Top 10 framework entry'
  );
  assert.ok(
    sidebarContent.includes('owasp-ml-top10') || sidebarContent.includes('MLTOP10'),
    'Sidebar must render ML Top 10 framework entry'
  );
  assert.ok(
    sidebarContent.includes('owasp-agent-top10') || sidebarContent.includes('AGENTTOP10'),
    'Sidebar must render Agentic Top 10 framework entry'
  );
  assert.ok(
    sidebarContent.includes('owasp-saif-top10') || sidebarContent.includes('SAIFTOP10'),
    'Sidebar must render SAIF framework entry'
  );
  assert.ok(
    sidebarContent.includes('owasp-mcp-top10') || sidebarContent.includes('MCPTOP10'),
    'Sidebar must render MCP Top 10 framework entry'
  );
  assert.ok(
    sidebarContent.includes('secure-mcp-guide') || sidebarContent.includes('SECUREMCPGUIDE'),
    'Sidebar must render Secure MCP Guide framework entry'
  );
  assert.ok(
    sidebarContent.includes('genai-data-security') || sidebarContent.includes('GENAIDATASECURITY'),
    'Sidebar must render GenAI Data Security framework entry'
  );
});

test('Sidebar - renders utility navigation: Dashboard, Threat Model, Audit Checklist, Tools, Incidents', (t) => {
  const sidebarContent = readFile('components/Sidebar.tsx');

  assert.ok(sidebarContent.includes('onSelectDashboard'), 'Sidebar must support onSelectDashboard callback');
  assert.ok(sidebarContent.includes('onSelectThreatModel'), 'Sidebar must support onSelectThreatModel callback');
  assert.ok(sidebarContent.includes('onSelectAuditChecklist'), 'Sidebar must support onSelectAuditChecklist callback');
  assert.ok(sidebarContent.includes('onSelectTools'), 'Sidebar must support onSelectTools callback');
  assert.ok(sidebarContent.includes('onSelectIncidents'), 'Sidebar must support onSelectIncidents callback');
});

// ─── 3. Search Integration ────────────────────────────────────────────────────

test('Sidebar - integrates global omnisearch trigger with ⌘K hint', (t) => {
  const sidebarContent = readFile('components/Sidebar.tsx');

  assert.ok(sidebarContent.includes('onOpenSearch'), 'Sidebar must support onOpenSearch callback for global search');
  assert.ok(sidebarContent.includes('Search Nexus') || sidebarContent.includes('Search'), 'Sidebar must render search button label');
  assert.ok(sidebarContent.includes('⌘K') || sidebarContent.includes('Cmd+K') || sidebarContent.includes('⌘'), 'Sidebar must display ⌘K shortcut hint');
});

// ─── 4. Mobile Drawer & Overlay ──────────────────────────────────────────────

test('Sidebar - implements mobile drawer with open/close state and overlay', (t) => {
  const sidebarContent = readFile('components/Sidebar.tsx');

  assert.ok(sidebarContent.includes('isOpen'), 'Sidebar must accept isOpen prop for mobile drawer control');
  assert.ok(sidebarContent.includes('onClose'), 'Sidebar must accept onClose prop for mobile drawer close');

  // Mobile drawer CSS classes
  assert.ok(sidebarContent.includes('-translate-x-full'), 'Sidebar must use -translate-x-full when closed on mobile');
  assert.ok(sidebarContent.includes('md:translate-x-0'), 'Sidebar must be visible on md+ viewports');
  assert.ok(
    sidebarContent.includes('mobile-nav-overlay') || sidebarContent.includes('backdrop'),
    'Sidebar must render backdrop overlay on mobile'
  );
});

// ─── 5. Brand & Visual Identity ──────────────────────────────────────────────

test('Sidebar - renders official brand emblem (favicon.svg)', (t) => {
  const sidebarContent = readFile('components/Sidebar.tsx');

  assert.ok(sidebarContent.includes('favicon.svg'), 'Sidebar must render the official brand emblem (favicon.svg)');
});

// ─── 6. Props Interface Completeness ─────────────────────────────────────────

test('Sidebar - SidebarProps interface declares all required callback props', (t) => {
  const sidebarContent = readFile('components/Sidebar.tsx');

  const requiredProps = [
    'activePillar',
    'currentView',
    'onSelectPillar',
    'onSelectDashboard',
    'onSelectThreatModel',
    'onSelectAuditChecklist',
    'onSelectTools',
    'onSelectIncidents',
    'onOpenSearch',
    'isOpen',
    'onClose',
  ];

  for (const prop of requiredProps) {
    assert.ok(sidebarContent.includes(prop), `SidebarProps must declare '${prop}' prop`);
  }
});

// ─── 7. Active State Visual Indicator ────────────────────────────────────────

test('Sidebar - implements active state visual indicator for current view', (t) => {
  const sidebarContent = readFile('components/Sidebar.tsx');

  // Must differentiate active vs inactive items (via activePillar or currentView checks)
  assert.ok(
    sidebarContent.includes('activePillar') || sidebarContent.includes('currentView'),
    'Sidebar must use activePillar or currentView to highlight active navigation item'
  );

  // Must apply conditional class for active state
  const hasConditionalClass =
    sidebarContent.includes('? \'') ||
    sidebarContent.includes("? '") ||
    sidebarContent.includes('? "') ||
    sidebarContent.includes('clsx(') ||
    sidebarContent.includes('cn(');
  assert.ok(hasConditionalClass, 'Sidebar must apply conditional CSS classes for active state');
});

// ─── 8. Dashboard Hero Stat Cards Navigation ────────────────────────────────

test('Dashboard - Hero metric stat cards are interactive buttons redirecting to dedicated views', (t) => {
  const dashboardContent = readFile('components/Dashboard.tsx');

  // Must render stat cards as interactive buttons
  assert.ok(dashboardContent.includes('onSelectTools'), 'Dashboard must connect onSelectTools for tools metric card');
  assert.ok(dashboardContent.includes('onSelectIncidents'), 'Dashboard must connect onSelectIncidents for incidents metric card');
  assert.ok(dashboardContent.includes('onSelectThreatModel'), 'Dashboard must connect onSelectThreatModel for threats metric card');
  assert.ok(dashboardContent.includes('frameworks-section'), 'Dashboard must support scrolling to security standards section');

  // Verify all 6 stat cards have active click actions
  const requiredStatLabels = [
    'Test cases',
    'Attack payloads',
    'Framework threats',
    'Security standards',
    'Curated tools',
    'Real-world incidents'
  ];

  for (const label of requiredStatLabels) {
    assert.ok(dashboardContent.includes(`label: '${label}'`), `Dashboard must include stat card with label '${label}'`);
  }
});

// ─── 9. Menu Icons Color Styling ─────────────────────────────────────────────

test('Sidebar - All navigation menu icons have explicit color classes applied', (t) => {
  const sidebarContent = readFile('components/Sidebar.tsx');

  // 1. Overview & Dashboard, Threat Modelling, Audit Checklist
  assert.ok(
    sidebarContent.includes('<BookOpen className="w-4 h-4 shrink-0 text-cyan-400" />'),
    'Overview & Dashboard icon must have color class (text-cyan-400)'
  );
  assert.ok(
    sidebarContent.includes('<Shield className="w-4 h-4 shrink-0 text-indigo-400" />'),
    'Threat Modelling icon must have color class (text-indigo-400)'
  );
  assert.ok(
    sidebarContent.includes('<CheckCircle2 className="w-4 h-4 shrink-0 text-cyan-400" />'),
    'Audit Checklist icon must preserve color class (text-cyan-400)'
  );

  // 2. Frameworks & Top 10s (must preserve existing colors)
  assert.ok(sidebarContent.includes('<Brain className="w-4 h-4 shrink-0 text-pink-400" />'), 'LLM Top 10 icon must preserve text-pink-400');
  assert.ok(sidebarContent.includes('<Cpu className="w-4 h-4 shrink-0 text-emerald-400" />'), 'ML Top 10 icon must preserve text-emerald-400');
  assert.ok(sidebarContent.includes('<Bot className="w-4 h-4 shrink-0 text-orange-400" />'), 'Agentic Top 10 icon must preserve text-orange-400');
  assert.ok(sidebarContent.includes('<Network className="w-4 h-4 shrink-0 text-cyan-400" />'), 'MCP Top 10 icon must preserve text-cyan-400');
  assert.ok(sidebarContent.includes('<Database className="w-4 h-4 shrink-0 text-emerald-400" />'), 'GenAI Data Security icon must preserve text-emerald-400');
  assert.ok(sidebarContent.includes('<FileText className="w-4 h-4 shrink-0 text-cyan-300" />'), 'Secure MCP Guide icon must preserve text-cyan-300');
  assert.ok(sidebarContent.includes('<Gavel className="w-4 h-4 shrink-0 text-blue-400" />'), 'SAIF Risk Flow icon must preserve text-blue-400');

  // 3. Testing Pillars
  assert.ok(sidebarContent.includes('<BookOpen className="w-4 h-4 shrink-0 text-cyan-400" />'), 'All Tests icon must preserve text-cyan-400');
  assert.ok(sidebarContent.includes('color: "text-blue-400"'), 'Application Testing pillar must have text-blue-400');
  assert.ok(sidebarContent.includes('color: "text-purple-400"'), 'Model Testing pillar must have text-purple-400');
  assert.ok(sidebarContent.includes('color: "text-amber-400"'), 'Infrastructure Testing pillar must have text-amber-400');
  assert.ok(sidebarContent.includes('color: "text-emerald-400"'), 'Data Testing pillar must have text-emerald-400');
  assert.ok(sidebarContent.includes('<item.icon className={`w-4 h-4 shrink-0 ${item.color}`} />'), 'navItems must render icon with item.color');

  // 4. Intelligence & Catalogs
  assert.ok(sidebarContent.includes('<Terminal className="w-4 h-4 shrink-0 text-purple-400" />'), 'Security Tools Matrix icon must preserve text-purple-400');
  assert.ok(sidebarContent.includes('<Flame className="w-4 h-4 shrink-0 text-amber-400" />'), 'Real-World Incidents icon must preserve text-amber-400');

  // 5. Ensure no uncolored w-4 h-4 shrink-0 icons remain in Sidebar.tsx
  assert.ok(!sidebarContent.includes('className="w-4 h-4 shrink-0"'), 'Sidebar must not contain any uncolored w-4 h-4 shrink-0 icons');

  t.diagnostic('Verified all sidebar menu icons have explicit and preserved color classes');
});

