import * as fs from 'node:fs';
import { createHash } from 'node:crypto';
import type { MCPToolInfo } from '../types/mcp-scan.js';

export interface ToolPin {
  serverName: string;
  toolName: string;
  descriptionHash: string;
  pinnedAt: string;
  description: string;
}

export interface PinFile {
  version: 1;
  pins: ToolPin[];
}

export interface PinMismatch {
  toolName: string;
  serverName: string;
  expected: string;
  actual: string;
  previousDescription: string;
  currentDescription: string;
}

export interface PinCheckResult {
  matches: number;
  mismatches: PinMismatch[];
  newTools: string[];
  removedTools: string[];
}

function hashDescription(description: string): string {
  return createHash('sha256').update(description).digest('hex');
}

export function generatePins(tools: MCPToolInfo[], serverName?: string): PinFile {
  const pins: ToolPin[] = tools.map(tool => ({
    serverName: serverName ?? tool.file,
    toolName: tool.name,
    descriptionHash: hashDescription(tool.description),
    pinnedAt: new Date().toISOString(),
    description: tool.description,
  }));

  return { version: 1, pins };
}

export function checkPins(tools: MCPToolInfo[], pinFile: PinFile, serverName?: string): PinCheckResult {
  const mismatches: PinMismatch[] = [];
  const newTools: string[] = [];
  const removedTools: string[] = [];
  let matches = 0;

  const pinMap = new Map(pinFile.pins.map(p => [p.toolName, p]));
  const toolMap = new Map(tools.map(t => [t.name, t]));

  for (const tool of tools) {
    const pin = pinMap.get(tool.name);
    if (!pin) {
      newTools.push(tool.name);
      continue;
    }

    const currentHash = hashDescription(tool.description);
    if (currentHash === pin.descriptionHash) {
      matches++;
    } else {
      mismatches.push({
        toolName: tool.name,
        serverName: serverName ?? tool.file,
        expected: pin.descriptionHash,
        actual: currentHash,
        previousDescription: pin.description,
        currentDescription: tool.description,
      });
    }
  }

  for (const pin of pinFile.pins) {
    if (!toolMap.has(pin.toolName)) {
      removedTools.push(pin.toolName);
    }
  }

  return { matches, mismatches, newTools, removedTools };
}

export function loadPinFile(filePath: string): PinFile | null {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(content) as PinFile;
    if (parsed.version !== 1 || !Array.isArray(parsed.pins)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function savePinFile(pinFile: PinFile, filePath: string): void {
  fs.writeFileSync(filePath, JSON.stringify(pinFile, null, 2), 'utf-8');
}
