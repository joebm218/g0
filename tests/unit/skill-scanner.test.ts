import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { scanSkillFiles } from '../../src/mcp/skill-scanner.js';

const FIXTURE_DIR = path.resolve(__dirname, '../fixtures/mcp-system');

describe('SKILL.md Scanner', () => {
  it('detects malicious skill files', () => {
    const results = scanSkillFiles(FIXTURE_DIR);

    // Should find the SKILL.md fixture
    const skillFile = results.find(r => r.path.endsWith('SKILL.md'));
    expect(skillFile).toBeDefined();
    expect(skillFile!.findings.length).toBeGreaterThan(0);
  });

  it('detects hidden instructions in HTML comments', () => {
    const results = scanSkillFiles(FIXTURE_DIR);
    const skillFile = results.find(r => r.path.endsWith('SKILL.md'));
    const hiddenInstr = skillFile!.findings.find(f => f.type === 'skill-hidden-instructions');
    expect(hiddenInstr).toBeDefined();
    expect(hiddenInstr!.severity).toBe('critical');
  });

  it('detects prompt injection patterns', () => {
    const results = scanSkillFiles(FIXTURE_DIR);
    const skillFile = results.find(r => r.path.endsWith('SKILL.md'));
    const injections = skillFile!.findings.filter(f => f.type === 'skill-prompt-injection');
    expect(injections.length).toBeGreaterThan(0);
  });

  it('detects data exfiltration patterns', () => {
    const results = scanSkillFiles(FIXTURE_DIR);
    const skillFile = results.find(r => r.path.endsWith('SKILL.md'));
    const exfil = skillFile!.findings.filter(f => f.type === 'skill-data-exfil');
    expect(exfil.length).toBeGreaterThan(0);
  });

  it('detects excessive permission requests', () => {
    const results = scanSkillFiles(FIXTURE_DIR);
    const skillFile = results.find(r => r.path.endsWith('SKILL.md'));
    const perms = skillFile!.findings.filter(f => f.type === 'skill-excessive-permissions');
    expect(perms.length).toBeGreaterThan(0);
  });

  it('detects base64 obfuscated content', () => {
    const results = scanSkillFiles(FIXTURE_DIR);
    const skillFile = results.find(r => r.path.endsWith('SKILL.md'));
    const obfuscated = skillFile!.findings.filter(f => f.type === 'skill-obfuscated-content');
    expect(obfuscated.length).toBeGreaterThan(0);
  });

  it('returns empty for directory without skill files', () => {
    const results = scanSkillFiles('/tmp');
    // /tmp likely has no SKILL.md or .claude/skills
    expect(results).toEqual([]);
  });
});
