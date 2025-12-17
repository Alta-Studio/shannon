// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Shannon Helper MCP Server
 *
 * In-process MCP server providing save_deliverable and generate_totp tools
 * for Shannon penetration testing agents.
 *
 * Replaces bash script invocations with native tool access.
 */

import { createSdkMcpServer } from '@anthropic-ai/claude-agent-sdk';
import { saveDeliverableTool } from './tools/save-deliverable.js';
import { generateTotpTool } from './tools/generate-totp.js';

/**
 * Create Shannon Helper MCP Server with target directory context
 *
 * @param {string} targetDir - The target repository directory where deliverables should be saved
 * @param {string} runId - Optional run ID for timestamped directory structure
 * @returns {Object} MCP server instance
 */
export function createShannonHelperServer(targetDir, runId = null) {
  // Store target directory and run ID for tool access
  global.__SHANNON_TARGET_DIR = targetDir;
  global.__SHANNON_RUN_ID = runId;

  return createSdkMcpServer({
    name: 'shannon-helper',
    version: '1.0.0',
    tools: [saveDeliverableTool, generateTotpTool],
  });
}

// Export tools for direct usage if needed
export { saveDeliverableTool, generateTotpTool };

// Export types for external use
export * from './types/index.js';
