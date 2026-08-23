#!/usr/bin/env node

/**
 * AI Security Nexus - Automated Link Health & Availability Tester
 * 
 * Verifies live HTTP status for all URLs in incidents_catalog.ts and tools_catalog.ts.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

async function testUrl(url) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    let res = await fetch(url, {
      method: 'HEAD',
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      signal: controller.signal,
      redirect: 'follow'
    }).catch(async () => {
      // If HEAD fails or is forbidden, try GET
      return await fetch(url, {
        method: 'GET',
        headers: {
          'User-Agent': USER_AGENT,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        },
        signal: controller.signal,
        redirect: 'follow'
      });
    });

    clearTimeout(timeout);

    // If 405 (Method Not Allowed) or 403 on HEAD, try GET
    if (res.status === 405 || res.status === 403) {
      const getController = new AbortController();
      const getTimeout = setTimeout(() => getController.abort(), 10000);
      try {
        res = await fetch(url, {
          method: 'GET',
          headers: {
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
          },
          signal: getController.signal,
          redirect: 'follow'
        });
      } finally {
        clearTimeout(getTimeout);
      }
    }

    return {
      url,
      ok: res.status >= 200 && res.status < 400,
      status: res.status,
      statusText: res.statusText
    };
  } catch (err) {
    return {
      url,
      ok: false,
      status: 'ERROR',
      error: err.message
    };
  }
}

async function checkFileUrls(relativePath) {
  const filePath = path.join(rootDir, relativePath);
  const content = fs.readFileSync(filePath, 'utf8');
  const matches = [...content.matchAll(/url:\s*["'](https?:\/\/[^"']+)["']/g)];
  const urls = [...new Set(matches.map(m => m[1]))];

  console.log(`\n============================================================`);
  console.log(`🔍 Checking ${urls.length} unique URLs in ${relativePath}`);
  console.log(`============================================================\n`);

  const results = [];
  const BATCH_SIZE = 10;

  for (let i = 0; i < urls.length; i += BATCH_SIZE) {
    const batch = urls.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(batch.map(url => testUrl(url)));
    
    for (const r of batchResults) {
      results.push(r);
      if (r.ok) {
        console.log(`\x1b[32m✔ [${r.status}]\x1b[0m ${r.url}`);
      } else {
        console.log(`\x1b[31m✖ [${r.status}]\x1b[0m ${r.url} ${r.error ? `(${r.error})` : ''}`);
      }
    }
  }

  const failures = results.filter(r => !r.ok);
  console.log(`\n------------------------------------------------------------`);
  console.log(`Summary for ${relativePath}: ${results.length - failures.length} Passed, ${failures.length} Failed`);
  console.log(`------------------------------------------------------------\n`);

  return { results, failures };
}

async function main() {
  const incidentReport = await checkFileUrls('incidents_catalog.ts');
  const toolReport = await checkFileUrls('tools_catalog.ts');
  
  const totalFailures = incidentReport.failures.length + toolReport.failures.length;

  if (totalFailures > 0) {
    console.log(`\n❌ Total Failed URLs: ${totalFailures}`);
    process.exit(1);
  } else {
    console.log(`\n🎉 100% of all URLs verified successfully!`);
    process.exit(0);
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
