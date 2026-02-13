import * as fs from 'node:fs';
import { resolveClientPaths } from './well-known-paths.js';
import { scanAllMCPConfigs } from './analyzer.js';
import type { MCPScanResult } from '../types/mcp-scan.js';

export interface WatcherOptions {
  debounceMs?: number;
  onUpdate: (result: MCPScanResult) => void;
  onError?: (error: Error) => void;
}

/**
 * Watch well-known MCP config files for changes and re-scan on modification.
 * Returns an abort function to stop watching.
 */
export function watchMCPConfigs(options: WatcherOptions): () => void {
  const debounceMs = options.debounceMs ?? 300;
  const watchers: fs.FSWatcher[] = [];
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  let stopped = false;

  const clients = resolveClientPaths();
  const existingPaths = clients.map(c => c.configPath);

  if (existingPaths.length === 0) {
    options.onError?.(new Error('No MCP config files found to watch'));
    return () => {};
  }

  function handleChange() {
    if (stopped) return;
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      try {
        const result = scanAllMCPConfigs();
        options.onUpdate(result);
      } catch (err) {
        options.onError?.(err instanceof Error ? err : new Error(String(err)));
      }
    }, debounceMs);
  }

  for (const configPath of existingPaths) {
    try {
      const watcher = fs.watch(configPath, { persistent: true }, () => {
        handleChange();
      });
      watchers.push(watcher);
    } catch {
      // File may not be watchable, skip
    }
  }

  // Return abort function
  return () => {
    stopped = true;
    if (debounceTimer) clearTimeout(debounceTimer);
    for (const watcher of watchers) {
      watcher.close();
    }
  };
}
