import * as fs from 'node:fs';
import type { InventoryDiff, InventoryDiffItem } from '../types/inventory-diff.js';

function statusEmoji(status: 'added' | 'removed' | 'changed'): string {
  switch (status) {
    case 'added': return '🟢';
    case 'removed': return '🔴';
    case 'changed': return '🟡';
  }
}

function mdSection<T>(title: string, items: InventoryDiffItem<T>[], nameFn: (item: T) => string): string {
  if (items.length === 0) return '';
  const lines: string[] = [`### ${title}\n`];
  lines.push('| Status | Item | Details |');
  lines.push('|--------|------|---------|');
  for (const item of items) {
    const ref = item.current ?? item.previous;
    if (!ref) continue;
    const name = nameFn(ref);
    const details = item.changes?.join('; ') ?? '';
    lines.push(`| ${statusEmoji(item.status)} ${item.status} | ${name} | ${details} |`);
  }
  lines.push('');
  return lines.join('\n');
}

export function reportInventoryDiffMarkdown(diff: InventoryDiff, outputPath?: string): string {
  const { summary } = diff;
  const lines: string[] = [
    '# Inventory Diff\n',
    `**+${summary.totalAdded} added** | **-${summary.totalRemoved} removed** | **~${summary.totalChanged} changed**\n`,
  ];

  lines.push(mdSection('Models', diff.models, m => `${m.name} (${m.provider})`));
  lines.push(mdSection('Frameworks', diff.frameworks, f => `${f.name}${f.version ? ` v${f.version}` : ''}`));
  lines.push(mdSection('Tools', diff.tools, t => `${t.name} [${t.framework}]`));
  lines.push(mdSection('Agents', diff.agents, a => `${a.name} [${a.framework}]`));
  lines.push(mdSection('MCP Servers', diff.mcpServers, s => s.name));
  lines.push(mdSection('Vector DBs', diff.vectorDBs, v => `${v.name} [${v.framework}]`));
  lines.push(mdSection('Risks', diff.risks, r => `[${r.level}] ${r.description}`));

  // Risk delta
  const deltas = Object.entries(summary.riskDelta).filter(([, v]) => v !== 0);
  if (deltas.length > 0) {
    lines.push('### Risk Delta\n');
    lines.push('| Level | Delta |');
    lines.push('|-------|-------|');
    for (const [level, delta] of deltas) {
      const sign = delta > 0 ? '+' : '';
      lines.push(`| ${level} | ${sign}${delta} |`);
    }
    lines.push('');
  }

  const md = lines.join('\n');

  if (outputPath) {
    fs.writeFileSync(outputPath, md, 'utf-8');
  }

  return md;
}
