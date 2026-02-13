import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { scanMCPConfig } from '../../src/mcp/config-scanner.js';
import { scanMCPServerSource } from '../../src/mcp/source-scanner.js';
import { scanMCPConfigFile, scanMCPServer } from '../../src/mcp/analyzer.js';
import { reportMCPJson } from '../../src/reporters/mcp-json.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('scanMCPConfig', () => {
  it('detects npx auto-install', () => {
    const { servers, findings } = scanMCPConfig(
      path.join(FIXTURES, 'mcp-system/claude_desktop_config.json'),
      'Claude Desktop',
      'mcpServers',
    );

    expect(servers.length).toBe(3);
    const npxFindings = findings.filter(f => f.type === 'npx-auto-install');
    expect(npxFindings.length).toBeGreaterThan(0);
  });

  it('detects hardcoded secrets', () => {
    const { findings } = scanMCPConfig(
      path.join(FIXTURES, 'mcp-system/claude_desktop_config.json'),
      'Claude Desktop',
      'mcpServers',
    );

    const secretFindings = findings.filter(f => f.type === 'hardcoded-secret');
    expect(secretFindings.length).toBeGreaterThan(0);
    expect(secretFindings[0].severity).toBe('critical');
  });

  it('detects unpinned packages', () => {
    const { findings } = scanMCPConfig(
      path.join(FIXTURES, 'mcp-system/claude_desktop_config.json'),
      'Claude Desktop',
      'mcpServers',
    );

    const unpinned = findings.filter(f => f.type === 'unpinned-package');
    expect(unpinned.length).toBeGreaterThan(0);
  });

  it('marks safe servers as ok', () => {
    const { servers } = scanMCPConfig(
      path.join(FIXTURES, 'mcp-system/claude_desktop_config.json'),
      'Claude Desktop',
      'mcpServers',
    );

    const safeServer = servers.find(s => s.name === 'safe-server');
    expect(safeServer).toBeTruthy();
    expect(safeServer?.status).toBe('ok');
  });

  it('handles good config without findings', () => {
    const { servers, findings } = scanMCPConfig(
      path.join(FIXTURES, 'mcp-system/cursor-mcp.json'),
      'Cursor',
      'mcpServers',
    );

    expect(servers.length).toBe(1);
    expect(findings.length).toBe(0);
    expect(servers[0].status).toBe('ok');
  });
});

describe('scanMCPServerSource', () => {
  it('detects shell execution in vulnerable server', () => {
    const { tools, findings } = scanMCPServerSource(
      path.join(FIXTURES, 'mcp-system/vulnerable-server.py'),
      'vulnerable-server',
    );

    expect(tools.length).toBe(3);
    const shellFindings = findings.filter(f => f.type === 'shell-execution');
    expect(shellFindings.length).toBeGreaterThan(0);
  });

  it('detects code execution', () => {
    const { findings } = scanMCPServerSource(
      path.join(FIXTURES, 'mcp-system/vulnerable-server.py'),
      'vulnerable-server',
    );

    const codeExec = findings.filter(f => f.type === 'code-execution');
    expect(codeExec.length).toBeGreaterThan(0);
  });

  it('extracts tool descriptions', () => {
    const { tools } = scanMCPServerSource(
      path.join(FIXTURES, 'mcp-system/vulnerable-server.py'),
      'vulnerable-server',
    );

    const shellTool = tools.find(t => t.name === 'exec_shell');
    expect(shellTool).toBeTruthy();
    expect(shellTool?.description).toContain('shell command');
  });

  it('scans safe server with fewer findings', () => {
    const { tools, findings } = scanMCPServerSource(
      path.join(FIXTURES, 'mcp-system/safe-server.py'),
      'safe-server',
    );

    expect(tools.length).toBeGreaterThan(0);
    // Safe server should have no critical findings
    const critFindings = findings.filter(f => f.severity === 'critical');
    expect(critFindings.length).toBe(0);
  });
});

describe('MCP analyzer integration', () => {
  it('scanMCPConfigFile produces complete result', () => {
    const result = scanMCPConfigFile(
      path.join(FIXTURES, 'mcp-system/claude_desktop_config.json'),
    );

    expect(result.servers.length).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.summary.overallStatus).not.toBe('ok');
  });

  it('scanMCPServer scans source code', () => {
    const result = scanMCPServer(
      path.join(FIXTURES, 'mcp-system/vulnerable-server.py'),
    );

    expect(result.tools.length).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

describe('MCP JSON reporter', () => {
  it('produces valid JSON', () => {
    const result = scanMCPConfigFile(
      path.join(FIXTURES, 'mcp-system/claude_desktop_config.json'),
    );

    const json = reportMCPJson(result);
    const parsed = JSON.parse(json);
    expect(parsed.servers).toBeInstanceOf(Array);
    expect(parsed.findings).toBeInstanceOf(Array);
    expect(parsed.summary).toBeTruthy();
  });
});
