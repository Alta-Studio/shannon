# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Shannon is an AI-powered penetration testing agent for defensive security analysis. It automates vulnerability assessment by combining external reconnaissance tools with AI-powered code analysis and browser-based exploitation.

## Commands

### Installation & Running
```bash
npm install
./shannon.mjs <WEB_URL> <REPO_PATH> --config <CONFIG_FILE>
```

### Development Mode
```bash
# Pipeline testing mode - uses minimal prompts for fast testing
./shannon.mjs --pipeline-testing <command>

# Setup session only (no execution)
./shannon.mjs --setup-only <WEB_URL> <REPO_PATH> --config <CONFIG_FILE>
```

### Session Management
```bash
./shannon.mjs --status              # Show progress, timing, costs
./shannon.mjs --list-agents         # List all agents by phase
./shannon.mjs --run-all             # Run all remaining agents
./shannon.mjs --run-agent <name>    # Run specific agent
./shannon.mjs --run-phase <name>    # Run specific phase
./shannon.mjs --rerun <name>        # Rollback and re-execute agent
./shannon.mjs --rollback-to <name>  # Rollback to checkpoint
./shannon.mjs --cleanup             # Delete sessions
```

## Architecture

### Five-Phase Pipeline

```
shannon.mjs (orchestrator)
    │
    ├─► Phase 1: Pre-Reconnaissance (pre-recon)
    │   └─ External scans + source code analysis
    │
    ├─► Phase 2: Reconnaissance (recon)
    │   └─ Attack surface mapping
    │
    ├─► Phase 3: Vulnerability Analysis (5 parallel agents)
    │   └─ injection-vuln, xss-vuln, auth-vuln, authz-vuln, ssrf-vuln
    │
    ├─► Phase 4: Exploitation (5 parallel agents)
    │   └─ injection-exploit, xss-exploit, auth-exploit, authz-exploit, ssrf-exploit
    │
    └─► Phase 5: Reporting (report)
        └─ Executive summary generation
```

Phases 3 and 4 run agents in parallel with staggered starts (2s apart) for 5x faster execution.

### Core Components

| Module | Purpose |
|--------|---------|
| `shannon.mjs` | Main orchestrator - CLI parsing, phase sequencing |
| `src/session-manager.js` | Session state, agent definitions (AGENTS, PHASES), prerequisites |
| `src/checkpoint-manager.js` | Phase execution, parallel agent orchestration, git rollback |
| `src/ai/claude-executor.js` | Claude Agent SDK wrapper with retry logic and validation |
| `src/audit/` | Crash-safe logging system (source of truth) |
| `src/config-parser.js` | YAML config loading with JSON Schema validation |
| `mcp-server/` | Custom MCP tools (save_deliverable, generate_totp) |

### Data Flow

1. **Input**: Web URL + Local repo path + Config file
2. **State**: `.shannon-store.json` (minimal orchestration) + `audit-logs/` (full metrics)
3. **Output**: `deliverables/` in target repo (one file per agent)

### Agent Execution Flow

```
runClaudePromptWithRetry() in claude-executor.js:
  1. Create git checkpoint
  2. Initialize AuditSession (crash-safe logging)
  3. Call Claude Agent SDK with MCP servers
  4. Validate output via AGENT_VALIDATORS (src/constants.js)
  5. Commit or rollback based on success
  6. Mark agent completed in session
```

### MCP Server Integration

Each agent gets isolated browser instances via `MCP_AGENT_MAPPING` in `src/constants.js`:
- `playwright-agent1` through `playwright-agent5` for parallel execution
- `shannon-helper` provides `save_deliverable` and `generate_totp` tools

### Key Design Patterns

- **Session reuse**: Same URL+repo continues existing session unless completed
- **Fail-fast**: Missing prerequisites or validation failures stop execution
- **Self-healing**: `reconcileSession()` syncs Shannon store with audit logs on every command
- **Parallel safety**: `SessionMutex` prevents race conditions on state updates

## Configuration

YAML configs in `configs/` with JSON Schema validation (`configs/config-schema.json`):
- Authentication settings (form, SSO, API, basic auth, TOTP)
- Custom login flow instructions
- Rules for avoid/focus paths

## Prompts

Located in `prompts/`:
- `pre-recon-code.txt`, `recon.txt` - Early phases
- `vuln-{injection,xss,auth,authz,ssrf}.txt` - Vulnerability analysis
- `exploit-{injection,xss,auth,authz,ssrf}.txt` - Exploitation
- `report-executive.txt` - Final report
- `shared/` - Common includes (`_target.txt`, `_rules.txt`, `login-instructions.txt`)
- `pipeline-testing/` - Minimal prompts for fast development testing

## Error Handling

`src/error-handling.js` provides:
- `PentestError` class with type, retryable flag, and context
- `isRetryableError()` - Determines if SDK errors should retry
- `getRetryDelay()` - Exponential backoff with jitter

Retryable: network errors, rate limits (429), server errors, MCP failures
Non-retryable: auth errors, invalid API key, session limits

## Troubleshooting

| Error | Solution |
|-------|----------|
| "Agent already completed" | Use `--rerun <agent>` |
| "Missing prerequisites" | Run `--status` to see what's needed |
| "No sessions found" | Use `--setup-only` first |
| Corrupted state | Delete `.shannon-store.json` |

External tools (nmap, subfinder, whatweb) can be skipped with `--pipeline-testing`.
