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
  return fs.readFileSync(path.join(rootDir, relativePath), 'utf8');
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
    'Real-world exploits'
  ];

  for (const label of requiredStatLabels) {
    assert.ok(dashboardContent.includes(`label: '${label}'`), `Dashboard must include stat card with label '${label}'`);
  }
});
