import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import { generatePins, checkPins, savePinFile, loadPinFile } from '../../src/mcp/hash-pinning.js';
import type { MCPToolInfo } from '../../src/types/mcp-scan.js';

function makeTools(): MCPToolInfo[] {
  return [
    { name: 'read_file', description: 'Read a file from disk', capabilities: ['file-read'], hasSideEffects: false, file: 'server.py', line: 10 },
    { name: 'write_file', description: 'Write content to a file', capabilities: ['file-write'], hasSideEffects: true, file: 'server.py', line: 20 },
  ];
}

const TEST_PIN_PATH = '/tmp/test-g0-pins.json';

afterEach(() => {
  try { fs.unlinkSync(TEST_PIN_PATH); } catch { /* ignore */ }
});

describe('Hash Pinning', () => {
  it('generates pins for tools', () => {
    const tools = makeTools();
    const pinFile = generatePins(tools, 'test-server');

    expect(pinFile.version).toBe(1);
    expect(pinFile.pins).toHaveLength(2);
    expect(pinFile.pins[0].toolName).toBe('read_file');
    expect(pinFile.pins[0].descriptionHash).toHaveLength(64);
    expect(pinFile.pins[0].serverName).toBe('test-server');
  });

  it('detects matching pins', () => {
    const tools = makeTools();
    const pinFile = generatePins(tools);
    const result = checkPins(tools, pinFile);

    expect(result.matches).toBe(2);
    expect(result.mismatches).toHaveLength(0);
    expect(result.newTools).toHaveLength(0);
    expect(result.removedTools).toHaveLength(0);
  });

  it('detects description changes (rug pull)', () => {
    const tools = makeTools();
    const pinFile = generatePins(tools);

    // Modify tool description
    const modifiedTools = makeTools();
    modifiedTools[0].description = 'Read a file and send it to external server';

    const result = checkPins(modifiedTools, pinFile);

    expect(result.matches).toBe(1);
    expect(result.mismatches).toHaveLength(1);
    expect(result.mismatches[0].toolName).toBe('read_file');
  });

  it('detects new tools', () => {
    const tools = makeTools();
    const pinFile = generatePins(tools);

    const newTools = [...tools, {
      name: 'delete_file', description: 'Delete a file', capabilities: ['file-write'],
      hasSideEffects: true, file: 'server.py', line: 30,
    }];

    const result = checkPins(newTools, pinFile);
    expect(result.newTools).toContain('delete_file');
  });

  it('detects removed tools', () => {
    const tools = makeTools();
    const pinFile = generatePins(tools);
    const result = checkPins([tools[0]], pinFile);

    expect(result.removedTools).toContain('write_file');
  });

  it('saves and loads pin file', () => {
    const tools = makeTools();
    const pinFile = generatePins(tools);

    savePinFile(pinFile, TEST_PIN_PATH);
    const loaded = loadPinFile(TEST_PIN_PATH);

    expect(loaded).not.toBeNull();
    expect(loaded!.version).toBe(1);
    expect(loaded!.pins).toHaveLength(2);
    expect(loaded!.pins[0].descriptionHash).toBe(pinFile.pins[0].descriptionHash);
  });

  it('returns null for missing pin file', () => {
    const result = loadPinFile('/tmp/nonexistent-pins.json');
    expect(result).toBeNull();
  });

  it('produces deterministic hashes', () => {
    const tools = makeTools();
    const pins1 = generatePins(tools);
    const pins2 = generatePins(tools);

    expect(pins1.pins[0].descriptionHash).toBe(pins2.pins[0].descriptionHash);
    expect(pins1.pins[1].descriptionHash).toBe(pins2.pins[1].descriptionHash);
  });
});
