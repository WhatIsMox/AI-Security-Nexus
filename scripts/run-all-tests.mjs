#!/usr/bin/env node

/**
 * AI Security Nexus - Master Test Runner
 * 
 * Orchestrates all test suites across the application:
 * 1. Unit & Schema Tests (tests/unit/*.test.mjs)
 * 2. Functional & Logic Tests (tests/functional/*.test.mjs)
 * 3. Security & Hardening Tests (tests/security/*.test.mjs)
 * 4. Build & GitHub Pages Compatibility Tests (tests/build/*.test.mjs)
 */

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const testSuites = [
  { name: 'Unit & Schema Tests', pattern: 'tests/unit/*.test.mjs' },
  { name: 'Functional & Routing Tests', pattern: 'tests/functional/*.test.mjs' },
  { name: 'Security & CSP Tests', pattern: 'tests/security/*.test.mjs' },
  { name: 'Build & GitHub Pages Tests', pattern: 'tests/build/*.test.mjs' },
];

console.log('============================================================');
console.log('🧪 AI Security Nexus - Executing Master Test Suite');
console.log('============================================================\n');

function runTest(suite) {
  return new Promise((resolve) => {
    const start = Date.now();
    console.log(`▶ Running ${suite.name}...`);
    
    const proc = spawn(process.execPath, ['--test', ...suite.files], {
      cwd: rootDir,
      stdio: 'inherit'
    });

    proc.on('close', (code) => {
      const duration = ((Date.now() - start) / 1000).toFixed(2);
      if (code === 0) {
        console.log(`\x1b[32m✔ ${suite.name} Passed (${duration}s)\x1b[0m\n`);
        resolve(true);
      } else {
        console.log(`\x1b[31m✖ ${suite.name} Failed with exit code ${code} (${duration}s)\x1b[0m\n`);
        resolve(false);
      }
    });
  });
}

import fs from 'node:fs';

async function main() {
  let allPassed = true;

  for (const suite of testSuites) {
    const dir = path.join(rootDir, suite.pattern.split('/')[0], suite.pattern.split('/')[1]);
    if (fs.existsSync(dir)) {
      const files = fs.readdirSync(dir)
        .filter(f => f.endsWith('.test.mjs'))
        .map(f => path.join(dir, f));
      
      suite.files = files;
      const passed = await runTest(suite);
      if (!passed) allPassed = false;
    }
  }

  console.log('============================================================');
  if (allPassed) {
    console.log('\x1b[32m🎉 All Test Suites Passed Successfully!\x1b[0m');
    process.exit(0);
  } else {
    console.error('\x1b[31m❌ One or more test suites failed.\x1b[0m');
    process.exit(1);
  }
}

main();
