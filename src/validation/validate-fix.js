// Copyright (C) 2025 Alta Studio
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from 'zx';
import chalk from 'chalk';
import { PentestError } from '../error-handling.js';

// Map vulnerability type prefixes to queue file names
const VULN_TYPE_MAP = {
  'xss': 'xss',
  'auth': 'auth',
  'authz': 'authz',
  'injection': 'injection',
  'ssrf': 'ssrf'
};

/**
 * Parse vulnerability ID and extract type
 * @param {string} vulnId - e.g., "XSS-VULN-01"
 * @returns {{ type: string, id: string }}
 */
export function parseVulnId(vulnId) {
  const normalized = vulnId.toUpperCase().trim();
  const match = normalized.match(/^(XSS|AUTH|AUTHZ|INJECTION|SSRF)-VULN-(\d+)$/);

  if (!match) {
    throw new PentestError(
      `Invalid vulnerability ID format: ${vulnId}. Expected format: TYPE-VULN-NN (e.g., XSS-VULN-01, AUTH-VULN-03)`,
      'validation',
      false,
      { vulnId, expectedFormat: 'TYPE-VULN-NN' }
    );
  }

  return {
    type: match[1].toLowerCase(),
    id: normalized
  };
}

/**
 * Get the deliverables directory path
 * Priority: 1) --run-id flag, 2) 'latest' symlink, 3) flat structure
 * @param {string} sourceDir - target repository path
 * @returns {Promise<string>}
 */
async function getDeliverablesPath(sourceDir) {
  // If a specific run ID was provided via --run-id flag, use that
  const runId = global.SHANNON_RUN_ID;
  if (runId) {
    const runPath = path.join(sourceDir, 'deliverables', 'runs', runId);
    if (await fs.pathExists(runPath)) {
      return runPath;
    }
    // Run ID specified but doesn't exist - warn and fall through
    console.log(chalk.yellow(`⚠️ Run ID '${runId}' not found, falling back to latest`));
  }

  // Check if 'latest' symlink exists (new timestamped structure)
  const latestPath = path.join(sourceDir, 'deliverables', 'latest');
  if (await fs.pathExists(latestPath)) {
    return latestPath;
  }

  // Fall back to flat structure for backwards compatibility
  return path.join(sourceDir, 'deliverables');
}

/**
 * Get the queue file path for a vulnerability type
 * @param {string} vulnType - e.g., "xss"
 * @param {string} sourceDir - target repository path
 * @returns {Promise<string>}
 */
export async function getQueueFilePath(vulnType, sourceDir) {
  const mappedType = VULN_TYPE_MAP[vulnType.toLowerCase()];
  if (!mappedType) {
    throw new PentestError(
      `Unknown vulnerability type: ${vulnType}`,
      'validation',
      false,
      { vulnType, validTypes: Object.keys(VULN_TYPE_MAP) }
    );
  }
  const deliverablesPath = await getDeliverablesPath(sourceDir);
  return path.join(deliverablesPath, `${mappedType}_exploitation_queue.json`);
}

/**
 * Get a single vulnerability from its queue file
 * @param {string} vulnId - e.g., "XSS-VULN-01"
 * @param {string} sourceDir - target repository path
 * @returns {Promise<Object>} vulnerability object
 */
export async function getVulnerabilityFromQueue(vulnId, sourceDir) {
  const { type, id } = parseVulnId(vulnId);
  const queuePath = await getQueueFilePath(type, sourceDir);

  if (!await fs.pathExists(queuePath)) {
    throw new PentestError(
      `Queue file not found: ${queuePath}. Run vulnerability analysis first.`,
      'validation',
      false,
      { queuePath, vulnId }
    );
  }

  const queue = await fs.readJSON(queuePath);

  if (!queue.vulnerabilities || !Array.isArray(queue.vulnerabilities)) {
    throw new PentestError(
      `Invalid queue file format: ${queuePath}`,
      'validation',
      false,
      { queuePath }
    );
  }

  const vuln = queue.vulnerabilities.find(v => v.ID === id);

  if (!vuln) {
    throw new PentestError(
      `Vulnerability ${id} not found in queue. Available IDs: ${queue.vulnerabilities.map(v => v.ID).join(', ')}`,
      'validation',
      false,
      { vulnId: id, availableIds: queue.vulnerabilities.map(v => v.ID) }
    );
  }

  return { ...vuln, _queuePath: queuePath, _type: type };
}

/**
 * List all vulnerability IDs from all queue files
 * @param {string} sourceDir - target repository path
 * @returns {Promise<Array<{id: string, type: string, description: string}>>}
 */
export async function listAllVulnerabilities(sourceDir) {
  const deliverablesDir = await getDeliverablesPath(sourceDir);

  if (!await fs.pathExists(deliverablesDir)) {
    console.log(chalk.yellow('No deliverables directory found. Run vulnerability analysis first.'));
    return [];
  }

  const allVulns = [];

  for (const vulnType of Object.keys(VULN_TYPE_MAP)) {
    const queuePath = await getQueueFilePath(vulnType, sourceDir);

    if (await fs.pathExists(queuePath)) {
      try {
        const queue = await fs.readJSON(queuePath);
        if (queue.vulnerabilities && Array.isArray(queue.vulnerabilities)) {
          for (const vuln of queue.vulnerabilities) {
            allVulns.push({
              id: vuln.ID,
              type: vulnType.toUpperCase(),
              vulnerabilityType: vuln.vulnerability_type || 'Unknown',
              source: vuln.source || vuln.source_detail || 'Unknown',
              confidence: vuln.confidence || 'Unknown',
              verdict: vuln.verdict || 'Unknown'
            });
          }
        }
      } catch (error) {
        console.log(chalk.yellow(`Warning: Could not read ${queuePath}: ${error.message}`));
      }
    }
  }

  return allVulns;
}

/**
 * Display vulnerability list in a nice table format
 * @param {string} sourceDir - target repository path
 */
export async function displayVulnerabilityList(sourceDir) {
  const vulns = await listAllVulnerabilities(sourceDir);

  if (vulns.length === 0) {
    console.log(chalk.yellow('\nNo vulnerabilities found in queue files.'));
    console.log(chalk.gray('Run vulnerability analysis phase first: ./shannon.mjs --run-phase vulnerability-analysis'));
    return;
  }

  console.log(chalk.cyan.bold('\n📋 Available Vulnerabilities for Validation\n'));
  console.log(chalk.gray('─'.repeat(90)));
  console.log(chalk.bold('ID               Type          Subtype        Confidence   Verdict      Source'));
  console.log(chalk.gray('─'.repeat(90)));

  for (const vuln of vulns) {
    const idPadded = vuln.id.padEnd(16);
    const typePadded = vuln.type.padEnd(13);
    const subtypePadded = (vuln.vulnerabilityType || '-').substring(0, 14).padEnd(14);
    const confPadded = (vuln.confidence || '-').padEnd(12);
    const verdictPadded = (vuln.verdict || '-').padEnd(12);
    const source = (vuln.source || '-').substring(0, 25);

    const color = vuln.verdict === 'vulnerable' ? chalk.red : chalk.green;
    console.log(`${color(idPadded)} ${typePadded} ${subtypePadded} ${confPadded} ${verdictPadded} ${chalk.gray(source)}`);
  }

  console.log(chalk.gray('─'.repeat(90)));
  console.log(chalk.gray(`\nTotal: ${vulns.length} vulnerabilities`));
  console.log(chalk.cyan('\nUsage: ./shannon.mjs --validate <VULN-ID>'));
  console.log(chalk.gray('Example: ./shannon.mjs --validate XSS-VULN-01'));
}

/**
 * Generate a focused validation prompt for a single vulnerability
 * @param {Object} vuln - vulnerability object from queue
 * @param {string} webUrl - target web URL
 * @param {Object} config - optional distributed config with auth info
 * @returns {string} prompt text
 */
export function generateValidationPrompt(vuln, webUrl, config = null) {
  // Build authentication section if config provided
  let authSection = '';
  if (config && config.authentication) {
    const auth = config.authentication;

    // Build login URL - use webUrl base if config has docker-specific URL
    let loginUrl = auth.login_url || `${webUrl}/login`;
    if (loginUrl.includes('host.docker.internal')) {
      // Replace docker host with actual webUrl host
      const webUrlObj = new URL(webUrl);
      loginUrl = loginUrl.replace(/host\.docker\.internal(:\d+)?/, webUrlObj.host);
    }

    authSection = `
## Authentication

**CRITICAL: You MUST authenticate FIRST before testing this vulnerability.**

### Step 1: Login to the Application

**Login URL**: ${loginUrl}

**Credentials**:
- Email: \`${auth.credentials.username}\`
- Password: \`${auth.credentials.password}\`
`;

    if (auth.credentials.totp_secret) {
      authSection += `
**MFA**: If prompted for a verification code, use the \`generate_totp\` MCP tool.
`;
    }

    if (auth.login_flow && auth.login_flow.length > 0) {
      authSection += `
**Login Steps**:
`;
      auth.login_flow.forEach((step, i) => {
        // Replace $username and $password placeholders
        let expandedStep = step
          .replace(/\$username/g, auth.credentials.username)
          .replace(/\$password/g, auth.credentials.password);
        authSection += `${i + 1}. ${expandedStep}\n`;
      });
    }

    authSection += `
### Step 2: Verify Login Success
After logging in, verify you are authenticated before proceeding to test the vulnerability.

---
`;
  }

  return `# Vulnerability Fix Validation

## Objective
You are validating whether a SPECIFIC vulnerability has been fixed. Your ONLY task is to test this ONE vulnerability and determine if it still exists.

## Target
- **Web URL**: ${webUrl}
- **Vulnerability ID**: ${vuln.ID}
- **Type**: ${vuln.vulnerability_type || vuln._type}
${authSection}
## Vulnerability Details
\`\`\`json
${JSON.stringify(vuln, null, 2)}
\`\`\`

## Instructions

1. **Authenticate** using the credentials above (if provided)
2. **Navigate** to the vulnerable endpoint/page
3. **Reproduce** the vulnerability using the witness payload or similar test
4. **Observe** whether the vulnerability still triggers
5. **Document** your findings

## Success Criteria
- If the vulnerability NO LONGER triggers: Report as **FIXED**
- If the vulnerability STILL triggers: Report as **STILL VULNERABLE**
- If you cannot test (e.g., endpoint removed): Report as **CANNOT TEST** with reason

## Output
Create a file at \`deliverables/validation_result_${vuln.ID}.json\` with this structure:
\`\`\`json
{
  "vuln_id": "${vuln.ID}",
  "validation_timestamp": "<ISO timestamp>",
  "status": "FIXED" | "STILL_VULNERABLE" | "CANNOT_TEST",
  "evidence": "<description of what you observed>",
  "test_performed": "<description of the test you ran>",
  "recommendation": "<next steps if still vulnerable>"
}
\`\`\`

## Important
- Focus ONLY on this specific vulnerability
- Do not scan for other issues
- Be thorough in your testing but stay focused
- Document your exact test steps for reproducibility
`;
}

/**
 * Save validation results
 * @param {string} sourceDir - target repository path
 * @param {Object} result - validation result object
 */
export async function saveValidationResult(sourceDir, result) {
  const resultsDir = path.join(sourceDir, 'deliverables');
  await fs.ensureDir(resultsDir);

  const resultPath = path.join(resultsDir, `validation_result_${result.vuln_id}.json`);
  await fs.writeJSON(resultPath, result, { spaces: 2 });

  console.log(chalk.green(`\n✅ Validation result saved to: ${resultPath}`));
  return resultPath;
}
