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

test('Mobile Responsiveness - Viewport Meta & HTML Head Configuration', (t) => {
  const indexHtml = readFile('index.html');
  assert.ok(indexHtml.includes('name="viewport"'), 'index.html must include viewport meta tag');
  assert.ok(indexHtml.includes('width=device-width'), 'viewport must specify width=device-width');
  assert.ok(indexHtml.includes('initial-scale=1.0'), 'viewport must specify initial-scale=1.0');
});

test('Mobile Responsiveness - ToolDetailModal Layout & Touch Scrolling', (t) => {
  const modalContent = readFile('components/ToolDetailModal.tsx');

  // Assert top menu bar / notch clearance & dynamic viewport height
  assert.ok(modalContent.includes('safe-area-inset-top') || modalContent.includes('pt-[calc'), 'Modal must include safe area top clearance to avoid getting hidden under mobile menu bar');
  assert.ok(modalContent.includes('overflow-y-auto'), 'Modal must have vertical scrolling container');
  
  // Assert responsive padding and sticky access
  assert.ok(modalContent.includes('sticky top-0 z-20'), 'Modal header must be sticky for immediate close access on mobile');
  assert.ok(modalContent.includes('min-w-[36px] min-h-[36px]'), 'Close button must satisfy accessible tap target height');

  // Assert typography responsiveness
  assert.ok(modalContent.includes('break-words'), 'Title must specify break-words to prevent overflow on small screens');
  assert.ok(modalContent.includes('text-lg sm:text-2xl'), 'Title font size must scale responsively');

  // Assert code block overflow handling
  assert.ok(modalContent.includes('overflow-x-auto'), 'Installation code block must specify overflow-x-auto');
});

test('Mobile Responsiveness - IncidentDetailModal Layout & Touch Scrolling', (t) => {
  const modalContent = readFile('components/IncidentDetailModal.tsx');

  // Assert top menu bar / notch clearance & dynamic viewport height
  assert.ok(modalContent.includes('safe-area-inset-top') || modalContent.includes('pt-[calc'), 'Incident modal must include safe area top clearance to prevent hiding under mobile menu bar');
  assert.ok(modalContent.includes('overflow-y-auto'), 'Incident modal must be vertically scrollable');

  // Assert sticky header and close button ergonomics
  assert.ok(modalContent.includes('sticky top-0 z-20'), 'Incident modal header must be sticky');
  assert.ok(modalContent.includes('min-w-[36px] min-h-[36px]'), 'Incident close button must meet touch target sizes');

  // Assert responsive text scaling & wrapping
  assert.ok(modalContent.includes('text-base sm:text-xl md:text-2xl'), 'Incident modal title must scale gracefully on mobile');
  assert.ok(modalContent.includes('break-words'), 'Incident title must wrap cleanly on narrow screens');
  assert.ok(modalContent.includes('grid-cols-1 sm:grid-cols-2'), 'Recovery vs Fallout boxes must stack in single column on mobile');
});

test('Mobile Responsiveness - ThreatDetailModal Layout & Touch Scrolling', (t) => {
  const modalContent = readFile('components/ThreatDetailModal.tsx');

  // Assert top menu bar / notch clearance & dynamic viewport height
  assert.ok(modalContent.includes('safe-area-inset-top') || modalContent.includes('pt-[calc'), 'Threat modal must include safe area top clearance to prevent hiding under mobile menu bar');
  assert.ok(modalContent.includes('overflow-y-auto'), 'Threat modal must be vertically scrollable');

  // Assert sticky header and close button ergonomics
  assert.ok(modalContent.includes('sticky top-0 z-20'), 'Threat modal header must be sticky');
  assert.ok(modalContent.includes('break-words'), 'Threat title must wrap cleanly on narrow screens');
  assert.ok(modalContent.includes('grid-cols-1 lg:grid-cols-2'), 'Threat mechanics must stack responsively on mobile');
});

test('Mobile Responsiveness - Dashboard Charts, Radar & Architecture Bands', (t) => {
  const dashContent = readFile('components/Dashboard.tsx');

  // Assert severity chart responsive flex header
  assert.ok(dashContent.includes('flex-col sm:flex-row'), 'Dashboard chart headers must stack vertically on mobile');
  assert.ok(dashContent.includes('p-4 sm:p-6 md:p-8'), 'Dashboard risk and coverage cards must have responsive padding');

  // Assert Architecture Band & Pillar Nodes mobile layout
  assert.ok(dashContent.includes('p-3.5 sm:p-5'), 'Pillar node cards must have touch-friendly mobile padding');
  assert.ok(dashContent.includes('truncate'), 'Pillar node threats must be truncated to prevent card blowouts');

  // Assert Featured Spotlight payload code overflow
  assert.ok(dashContent.includes('break-words'), 'Spotlight title and code must break words');
  assert.ok(dashContent.includes('max-h-52 sm:max-h-none') || dashContent.includes('overflow-y-auto'), 'Spotlight payload preview must be scrollable on mobile');
});

test('Mobile Responsiveness - Global Omnisearch Modal & Filter Swiping', (t) => {
  const searchContent = readFile('components/GlobalSearchModal.tsx');

  // Assert search dialog mobile sizing and top clearance
  assert.ok(searchContent.includes('safe-area-inset-top') || searchContent.includes('pt-[calc'), 'Global search modal must include safe area top clearance');
  assert.ok(searchContent.includes('overflow-x-auto'), 'Filter category tabs must allow horizontal scrolling on mobile');
  assert.ok(searchContent.includes('line-clamp-2'), 'Search result subtitles must be line-clamped on mobile');
});

test('Mobile Responsiveness - Test Detail Payload Code Pre-blocks & Copy Controls', (t) => {
  const detailContent = readFile('components/TestDetail.tsx');

  // Assert payload code formatting
  assert.ok(detailContent.includes('overflow-x-auto'), 'Attack payload pre blocks must have horizontal scrolling');
  assert.ok(detailContent.includes('whitespace-pre-wrap break-words'), 'Payload text must wrap and break words');
  assert.ok(detailContent.includes('flex-col sm:flex-row'), 'Payload headers must wrap cleanly on mobile');
});

test('Mobile Responsiveness - Threat Modelling Architecture Layer Switcher', (t) => {
  const threatContent = readFile('components/ThreatModelling.tsx');

  // Assert presence of mobile dedicated layer selector and cards grid
  assert.ok(threatContent.includes('lg:hidden') && threatContent.includes('Architecture Explorer'), 'ThreatModelling must render mobile layer view when screen is below lg breakpoint');
  assert.ok(threatContent.includes('grid gap-3 p-4 sm:grid-cols-2'), 'ThreatModelling mobile component cards must be in a responsive grid');
});

test('Mobile Responsiveness - Sidebar Drawer Navigation & Overlay', (t) => {
  const sidebarContent = readFile('components/Sidebar.tsx');

  // Assert mobile drawer translation classes
  assert.ok(sidebarContent.includes('md:translate-x-0'), 'Sidebar must be visible on md+ viewports');
  assert.ok(sidebarContent.includes('-translate-x-full'), 'Sidebar must be hidden offscreen on mobile when closed');
  assert.ok(sidebarContent.includes('mobile-nav-overlay'), 'Sidebar must render backdrop overlay on mobile');
});
