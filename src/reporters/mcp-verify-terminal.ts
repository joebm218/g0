import chalk from 'chalk';
import type { MCPVerifyResult } from '../mcp/npm-verify.js';

export function reportMCPVerifyTerminal(result: MCPVerifyResult): void {
  console.log('');
  console.log(chalk.bold(`  MCP Package Verification: ${result.package}`));
  console.log(chalk.dim('  ' + '─'.repeat(55)));

  if (!result.found) {
    console.log(chalk.red.bold('  NOT FOUND'));
    for (const risk of result.risks) {
      console.log(chalk.red(`  ${risk.description}`));
    }
    console.log('');
    return;
  }

  // Package info
  console.log(`  ${chalk.dim('Version:')}      ${result.version}`);
  console.log(`  ${chalk.dim('Publisher:')}    ${result.publisher ?? 'unknown'}`);
  console.log(`  ${chalk.dim('Maintainers:')}  ${result.maintainers.join(', ') || 'none'}`);
  console.log(`  ${chalk.dim('License:')}      ${result.license ?? 'none'}`);

  if (result.repository) {
    console.log(`  ${chalk.dim('Repository:')}   ${result.repository}`);
  }

  if (result.publishedAt) {
    console.log(`  ${chalk.dim('Published:')}    ${result.publishedAt}`);
  }

  if (result.packageAge !== undefined) {
    console.log(`  ${chalk.dim('Package Age:')}  ${result.packageAge} days`);
  }

  if (result.weeklyDownloads !== undefined) {
    console.log(`  ${chalk.dim('Downloads/wk:')} ${result.weeklyDownloads.toLocaleString()}`);
  }

  console.log(`  ${chalk.dim('Dependencies:')} ${result.dependencies.length}`);

  if (result.hasInstallScripts) {
    console.log(`  ${chalk.dim('Install Scripts:')} ${chalk.yellow('YES')}`);
    for (const script of result.installScripts) {
      console.log(chalk.yellow(`    ${script}`));
    }
  }

  // Risks
  if (result.risks.length > 0) {
    console.log('');
    console.log(chalk.bold('  Risks'));
    console.log(chalk.dim('  ' + '─'.repeat(55)));

    for (const risk of result.risks) {
      const color = risk.severity === 'critical' ? chalk.red
        : risk.severity === 'high' ? chalk.red
        : risk.severity === 'medium' ? chalk.yellow
        : chalk.dim;
      const badge = risk.severity.toUpperCase().padEnd(8);
      console.log(`  ${color(badge)} ${risk.description}`);
    }
  }

  // Overall risk
  console.log('');
  const riskColor = result.overallRisk === 'critical' ? chalk.red.bold
    : result.overallRisk === 'high' ? chalk.red
    : result.overallRisk === 'medium' ? chalk.yellow
    : chalk.green;
  console.log(`  Overall Risk: ${riskColor(result.overallRisk.toUpperCase())}`);
  console.log('');
}
