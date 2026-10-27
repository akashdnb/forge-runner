const fs = require('node:fs');
const path = require('node:path');
const workflow = fs.readFileSync(path.join(__dirname, '.github/workflows/forge-public-runner.yml'), 'utf8');
const failures = [];
for (const match of workflow.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)\s*$/gm)) if (!/@[0-9a-f]{40}$/.test(match[1])) failures.push(`unpinned action: ${match[1]}`);
for (const forbidden of ['secrets: inherit', 'GITHUB_TOKEN', 'git@github.com:', 'FORGE_GITHUB_TOKEN']) if (workflow.includes(forbidden)) failures.push(`forbidden workflow capability: ${forbidden}`);
if (!/permissions:\s*\n\s+contents:\s+read/.test(workflow)) failures.push('workflow must have contents: read and no broader permissions');
if (!/timeout-minutes:\s+30/.test(workflow)) failures.push('workflow timeout missing');
if (!/cancel-in-progress:\s+true/.test(workflow)) failures.push('cancellation fencing missing');
if (failures.length) { console.error(failures.join('\n')); process.exit(1); }
console.log('forge-runner security audit: PASS');
