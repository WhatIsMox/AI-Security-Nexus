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

test('Security - GitHub Actions Least-Privilege Permissions', (t) => {
  const syncWorkflow = readFile('.github/workflows/agent-docs-sync.yml');
  const deployWorkflow = readFile('.github/workflows/deploy.yml');

  // Verify explicit top-level read restrictions
  assert.ok(syncWorkflow.includes('permissions:'), 'agent-docs-sync.yml must declare explicit permissions');
  assert.ok(syncWorkflow.includes('contents: read'), 'agent-docs-sync.yml top-level must default to contents: read');
  
  assert.ok(deployWorkflow.includes('permissions:'), 'deploy.yml must declare explicit permissions');
  assert.ok(deployWorkflow.includes('contents: read'), 'deploy.yml must restrict contents permission to read');
  assert.ok(deployWorkflow.includes('pages: write'), 'deploy.yml must specify pages: write');
  assert.ok(deployWorkflow.includes('id-token: write'), 'deploy.yml must specify id-token: write for OIDC');
});

test('Security - GitHub Actions Shell Injection Prevention', (t) => {
  const workflowDir = path.join(rootDir, '.github/workflows');
  const workflowFiles = fs.readdirSync(workflowDir).filter(f => f.endsWith('.yml') || f.endsWith('.yaml'));

  for (const file of workflowFiles) {
    const content = readFile(`.github/workflows/${file}`);
    const lines = content.split('\n');

    let inRun = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim().startsWith('run:')) {
        inRun = true;
      } else if (line.trim().startsWith('- name:') || line.trim().startsWith('uses:') || line.trim().startsWith('with:')) {
        inRun = false;
      }

      if (inRun) {
        // Assert no untrusted GitHub context variables are interpolated directly in shell commands
        assert.ok(
          !line.includes('${{ github.event.issue.body }}'),
          `File .github/workflows/${file} line ${i + 1} must not inline untrusted issue body in shell`
        );
        assert.ok(
          !line.includes('${{ github.event.comment.body }}'),
          `File .github/workflows/${file} line ${i + 1} must not inline untrusted comment body in shell`
        );
        assert.ok(
          !line.includes('${{ github.event.pull_request.title }}'),
          `File .github/workflows/${file} line ${i + 1} must not inline PR title directly in shell`
        );
      }
    }
  }
});

test('Security - GitHub Actions Concurrency Race-Condition Guards', (t) => {
  const syncWorkflow = readFile('.github/workflows/agent-docs-sync.yml');
  const deployWorkflow = readFile('.github/workflows/deploy.yml');

  assert.ok(syncWorkflow.includes('concurrency:'), 'agent-docs-sync.yml must specify concurrency guard');
  assert.ok(syncWorkflow.includes('cancel-in-progress: true'), 'agent-docs-sync.yml must cancel overlapping runs');

  assert.ok(deployWorkflow.includes('concurrency:'), 'deploy.yml must specify concurrency guard');
  assert.ok(deployWorkflow.includes('cancel-in-progress: true'), 'deploy.yml must cancel overlapping runs');
});
