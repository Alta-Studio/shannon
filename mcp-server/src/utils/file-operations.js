// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * File Operations Utilities
 *
 * Handles file system operations for deliverable saving.
 * Ported from tools/save_deliverable.js (lines 117-130).
 */

import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';

/**
 * Save deliverable file to deliverables/ directory
 * If a run ID is set, saves to deliverables/runs/{runId}/
 *
 * @param {string} filename - Name of the file to save
 * @param {string} content - Content to write to the file
 * @returns {string} Full path to the saved file
 */
export function saveDeliverableFile(filename, content) {
  // Use target directory from global context (set by createShannonHelperServer)
  const targetDir = global.__SHANNON_TARGET_DIR || process.cwd();
  const runId = global.__SHANNON_RUN_ID;

  // Determine deliverables directory based on whether run ID is set
  let deliverablesDir;
  if (runId) {
    // Timestamped run structure: deliverables/runs/{runId}/
    deliverablesDir = join(targetDir, 'deliverables', 'runs', runId);
  } else {
    // Legacy flat structure: deliverables/
    deliverablesDir = join(targetDir, 'deliverables');
  }

  const filepath = join(deliverablesDir, filename);

  // Ensure deliverables directory exists
  try {
    mkdirSync(deliverablesDir, { recursive: true });
  } catch (error) {
    // Directory might already exist, ignore
  }

  // Write file (atomic write - single operation)
  writeFileSync(filepath, content, 'utf8');

  return filepath;
}

/**
 * Get the current deliverables directory path
 * @returns {string} Path to the deliverables directory
 */
export function getDeliverablesDir() {
  const targetDir = global.__SHANNON_TARGET_DIR || process.cwd();
  const runId = global.__SHANNON_RUN_ID;

  if (runId) {
    return join(targetDir, 'deliverables', 'runs', runId);
  }
  return join(targetDir, 'deliverables');
}
