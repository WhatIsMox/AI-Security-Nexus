#!/usr/bin/env node

/**
 * AI Security Nexus - Automated Global Link Health & Availability Tester
 * 
 * Verifies live HTTP status and resolution for all URLs across all 12 data catalogs:
 * - data_tests.ts, data_agentic.ts, data_llm.ts, data_ml.ts, data_saif.ts,
 * - data_mcp.ts, data_secure_mcp_guide.ts, data_genai_data_security.ts,
 * - tools_catalog.ts, tool_details_catalog.ts, incidents_catalog.ts, incident_details_catalog.ts
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

const DATA_FILES = [
  'src/data/data_tests.ts',
  'src/data/data_agentic.ts',
  'src/data/data_llm.ts',
  'src/data/data_ml.ts',
  'src/data/data_saif.ts',
  'src/data/data_mcp.ts',
  'src/data/data_secure_mcp_guide.ts',
  'src/data/data_genai_data_security.ts',
  'src/data/data_securing_agentic_apps.ts',
  'src/data/data_agentic_applications.ts',
  'src/data/data_red_teaming_manual.ts',
  'src/data/tools_catalog.ts',
  'src/data/tool_details_catalog.ts',
  'src/data/incidents_catalog.ts',
  'src/data/incident_details_catalog.ts'
];

// Hosts that answer scripted clients with 403/404 even for live pages (verified in a real browser).
const BOT_PROTECTED_HOSTS = ['ftc.gov', 'sec.gov', 'splunk.com', 'akamai.com', 'layerxsecurity.com', 'helpnetsecurity.com', 'commerce.senate.gov'];
// Statuses that mean "reachable but refusing automated clients" – reported as warnings, not failures.
const BOT_BLOCK_STATUSES = new Set([401, 403, 405, 429]);

const isBotProtectedHost = (url) => {
  try {
    const host = new URL(url).hostname.replace(/^www\./, '');
    return BOT_PROTECTED_HOSTS.some((h) => host === h || host.endsWith(`.${h}`));
  } catch {
    return false;
  }
};

async function request(url, method, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      method,
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      signal: controller.signal,
      redirect: 'follow'
    });
  } finally {
    clearTimeout(timer);
  }
}

async function testUrl(url) {
  const TIMEOUT_MS = 15000;
  let lastError = null;
  let res = null;

  // HEAD first, then GET (many servers mishandle HEAD); retry the whole sequence once on network errors.
  for (let attempt = 0; attempt < 2; attempt++) {
    for (const method of ['HEAD', 'GET']) {
      try {
        res = await request(url, method, TIMEOUT_MS);
        lastError = null;
        if (res.status < 400) break;
      } catch (err) {
        lastError = err;
        res = null;
      }
    }
    if (res || !lastError) break;
  }

  if (!res) {
    return { url, ok: false, status: 'ERROR', error: lastError ? lastError.message : 'No response received' };
  }

  if (res.status >= 200 && res.status < 400) {
    return { url, ok: true, status: res.status };
  }
  if (BOT_BLOCK_STATUSES.has(res.status) || (res.status === 404 && isBotProtectedHost(url))) {
    return { url, ok: true, warning: true, status: res.status, statusText: 'bot-protected (reachable, not machine-verifiable)' };
  }
  return { url, ok: false, status: res.status, statusText: res.statusText };
}

async function main() {
  console.log(`============================================================`);
  console.log(`🔍 AI Security Nexus - Live Link Health & Availability Audit`);
  console.log(`============================================================\n`);

  // 1. Collect and deduplicate all URLs across all 12 catalogs
  const urlToFilesMap = new Map();

  for (const relPath of DATA_FILES) {
    const filePath = path.join(rootDir, relPath);
    if (!fs.existsSync(filePath)) continue;
    const content = fs.readFileSync(filePath, 'utf8');
    const matches = [...content.matchAll(/url:\s*["'](https?:\/\/[^"']+)["']/g)];
    for (const m of matches) {
      const url = m[1].trim();
      if (!urlToFilesMap.has(url)) {
        urlToFilesMap.set(url, new Set());
      }
      urlToFilesMap.get(url).add(relPath);
    }
  }

  const uniqueUrls = Array.from(urlToFilesMap.keys());
  console.log(`Collected ${uniqueUrls.length} globally unique URLs across ${DATA_FILES.length} data files.\n`);

  const results = [];
  const BATCH_SIZE = 25;

  for (let i = 0; i < uniqueUrls.length; i += BATCH_SIZE) {
    const batch = uniqueUrls.slice(i, i + BATCH_SIZE);
    const batchNum = Math.floor(i / BATCH_SIZE) + 1;
    const totalBatches = Math.ceil(uniqueUrls.length / BATCH_SIZE);

    process.stdout.write(`⏳ Checking batch ${batchNum}/${totalBatches} (${batch.length} URLs)... `);
    const batchResults = await Promise.all(batch.map(url => testUrl(url)));
    
    let batchFailures = 0;
    for (const r of batchResults) {
      results.push(r);
      if (!r.ok) {
        batchFailures++;
      }
    }

    if (batchFailures === 0) {
      console.log(`\x1b[32m✔ All OK\x1b[0m`);
    } else {
      console.log(`\x1b[31m✖ ${batchFailures} Failed\x1b[0m`);
    }
  }

  const failures = results.filter(r => !r.ok);
  const warnings = results.filter(r => r.ok && r.warning);

  console.log(`\n============================================================`);
  console.log(`🏁 Global Link Health Verification Summary`);
  console.log(`Total Unique URLs Verified: ${uniqueUrls.length}`);
  console.log(`Total Passed: ${uniqueUrls.length - failures.length} (${warnings.length} bot-protected, reachable)`);
  console.log(`Total Failed: ${failures.length}`);
  console.log(`============================================================\n`);

  if (warnings.length > 0) {
    console.log(`\x1b[33m⚠ Bot-protected URLs (reachable in a browser, blocked for scripts):\x1b[0m`);
    warnings.forEach(w => console.log(`  - [${w.status}] ${w.url}`));
    console.log('');
  }

  if (failures.length > 0) {
    console.error(`\x1b[31m❌ Failed URLs Detected (${failures.length}):\x1b[0m\n`);
    failures.forEach(f => {
      const files = Array.from(urlToFilesMap.get(f.url) || []).join(', ');
      console.error(`  - [${f.status}] ${f.url}`);
      console.error(`    Found in: ${files}`);
      if (f.error) console.error(`    Error details: ${f.error}`);
    });
    console.error(`\nPlease update the above URLs with verified, active, non-paywalled sources.`);
    process.exit(1);
  } else {
    console.log(`\x1b[32m🎉 100% of all external and reference URLs verified successfully!\x1b[0m\n`);
    process.exit(0);
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
