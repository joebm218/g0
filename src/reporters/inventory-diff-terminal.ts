import chalk from 'chalk';
import type { InventoryDiff, InventoryDiffItem } from '../types/inventory-diff.js';

function statusIcon(status: 'added' | 'removed' | 'changed'): string {
  switch (status) {
    case 'added': return chalk.green('+');
    case 'removed': return chalk.red('-');
    case 'changed': return chalk.yellow('~');
  }
}

function statusColor(status: 'added' | 'removed' | 'changed'): (text: string) => string {
  switch (status) {
    case 'added': return chalk.green;
    case 'removed': return chalk.red;
    case 'changed': return chalk.yellow;
  }
}

function printSection<T>(title: string, items: InventoryDiffItem<T>[], nameFn: (item: T) => string): void {
  if (items.length === 0) return;
  console.log(chalk.bold(`\n  ${title}`));
  console.log(chalk.dim('  ' + '─'.repeat(50)));
  for (const item of items) {
    const ref = item.current ?? item.previous;
    if (!ref) continue;
    const name = nameFn(ref);
    const color = statusColor(item.status);
    console.log(`  ${statusIcon(item.status)} ${color(name)}`);
    if (item.changes) {
      for (const change of item.changes) {
        console.log(chalk.dim(`      ${change}`));
      }
    }
  }
}

export function reportInventoryDiffTerminal(diff: InventoryDiff): void {
  console.log(chalk.bold('\n  Inventory Diff'));
  console.log(chalk.dim('  ' + '─'.repeat(50)));

  const { summary } = diff;
  console.log(`  ${chalk.green(`+${summary.totalAdded} added`)}  ${chalk.red(`-${summary.totalRemoved} removed`)}  ${chalk.yellow(`~${summary.totalChanged} changed`)}`);

  printSection('Models', diff.models, m => `${m.name} (${m.provider})`);
  printSection('Frameworks', diff.frameworks, f => `${f.name}${f.version ? ` v${f.version}` : ''}`);
  printSection('Tools', diff.tools, t => `${t.name} [${t.framework}]`);
  printSection('Agents', diff.agents, a => `${a.name} [${a.framework}]`);
  printSection('MCP Servers', diff.mcpServers, s => s.name);
  printSection('Vector DBs', diff.vectorDBs, v => `${v.name} [${v.framework}]`);
  printSection('Risks', diff.risks, r => `[${r.level}] ${r.description}`);

  // Risk delta
  const rd = summary.riskDelta;
  const deltas = Object.entries(rd).filter(([, v]) => v !== 0);
  if (deltas.length > 0) {
    console.log(chalk.bold('\n  Risk Delta'));
    console.log(chalk.dim('  ' + '─'.repeat(50)));
    for (const [level, delta] of deltas) {
      const sign = delta > 0 ? '+' : '';
      const color = delta > 0 ? chalk.red : chalk.green;
      console.log(`  ${level.padEnd(10)} ${color(`${sign}${delta}`)}`);
    }
  }

  console.log('');
}
