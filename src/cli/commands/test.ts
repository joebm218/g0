import * as path from 'node:path';
import chalk from 'chalk';
import { Command } from 'commander';
import { runTests } from '../../testing/engine.js';
import { buildStaticContext } from '../../testing/targeting.js';
import { reportTestTerminal } from '../../reporters/test-terminal.js';
import { reportTestJson } from '../../reporters/test-json.js';
import { getAIProvider } from '../../ai/provider.js';
import { createSpinner } from '../ui.js';
import { ALL_MUTATOR_IDS, type MutatorId } from '../../testing/mutators.js';
import type { AttackCategory, TestTarget, VerbosePhase } from '../../types/test.js';

export const testCommand = new Command('test')
  .description('Run adversarial security tests against a live AI agent')
  .option('--target <url>', 'HTTP endpoint to test')
  .option('--mcp <command>', 'MCP server command to test via stdio')
  .option('--mcp-args <args>', 'Comma-separated args for MCP command')
  .option('--auto [path]', 'Enable smart targeting via static scan (optional: project path)')
  .option('--attacks <categories>', 'Filter attack categories (comma-separated)')
  .option('--payloads <ids>', 'Run specific payload IDs (comma-separated)')
  .option('--ai', 'Enable LLM-as-judge for inconclusive results')
  .option('--json', 'Output as JSON')
  .option('-o, --output <file>', 'Write output to file')
  .option('--timeout <ms>', 'Per-payload timeout in milliseconds', '30000')
  .option('--header <header>', 'HTTP header (key:value), can be repeated', collectHeaders, {})
  .option('--message-field <field>', 'HTTP request body field name for message')
  .option('--response-field <field>', 'HTTP response field name to extract')
  .option('--openai', 'Use OpenAI chat completions format')
  .option('--model <name>', 'Model name for OpenAI mode (default: "gpt-4")')
  .option('--system-prompt <text>', 'System prompt for OpenAI mode')
  .option('--mutate [mutators]', 'Apply payload mutators (comma-separated: b64,r13,l33t,uconf,zw,spaced or "all")')
  .option('--verbose', 'Show request/response details during execution')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (options: {
    target?: string;
    mcp?: string;
    mcpArgs?: string;
    auto?: string | boolean;
    attacks?: string;
    payloads?: string;
    mutate?: string | boolean;
    ai?: boolean;
    json?: boolean;
    output?: string;
    timeout?: string;
    header?: Record<string, string>;
    messageField?: string;
    responseField?: string;
    openai?: boolean;
    model?: string;
    systemPrompt?: string;
    verbose?: boolean;
    banner?: boolean;
  }) => {
    // Validate: need either --target or --mcp
    if (!options.target && !options.mcp) {
      console.error(chalk.red('Error: Must specify --target <url> or --mcp <command>'));
      console.error(chalk.dim('\nExamples:'));
      console.error(chalk.dim('  g0 test --target http://localhost:8000'));
      console.error(chalk.dim('  g0 test --mcp python server.py'));
      console.error(chalk.dim('  g0 test --target http://localhost:8000 --auto ./my-agent'));
      console.error(chalk.dim('  g0 test --target http://localhost:8000 --openai --verbose'));
      process.exit(1);
    }

    // Build target
    const timeoutMs = parseInt(options.timeout ?? '30000', 10);
    const target: TestTarget = options.mcp
      ? {
          type: 'mcp-stdio',
          endpoint: options.mcp,
          args: options.mcpArgs?.split(',').map(a => a.trim()),
          name: `mcp:${options.mcp}`,
          timeout: timeoutMs,
        }
      : {
          type: 'http',
          endpoint: options.target!,
          headers: options.header,
          messageField: options.messageField,
          responseField: options.responseField,
          name: options.target,
          openai: options.openai,
          model: options.model,
          systemPrompt: options.systemPrompt,
        };

    // Parse attack categories
    const categories = options.attacks
      ? options.attacks.split(',').map(c => c.trim()) as AttackCategory[]
      : undefined;

    // Parse payload IDs
    const payloadIds = options.payloads
      ? options.payloads.split(',').map(id => id.trim())
      : undefined;

    // Parse mutators
    let mutators: MutatorId[] | undefined;
    if (options.mutate !== undefined) {
      if (options.mutate === true || options.mutate === 'all') {
        mutators = [...ALL_MUTATOR_IDS];
      } else if (typeof options.mutate === 'string') {
        mutators = options.mutate.split(',').map(m => m.trim()) as MutatorId[];
      }
    }

    // AI provider
    const aiProvider = options.ai ? getAIProvider() : null;
    if (options.ai && !aiProvider) {
      console.error(chalk.yellow('Warning: --ai flag set but no API key found (ANTHROPIC_API_KEY or OPENAI_API_KEY)'));
    }

    // Smart targeting: run static scan first
    let staticContext = undefined;
    if (options.auto !== undefined) {
      const scanPath = typeof options.auto === 'string' ? options.auto : '.';
      const resolvedPath = path.resolve(scanPath);

      const spinner = createSpinner('Running static scan for smart targeting...');
      spinner.start();

      try {
        // Dynamic import to avoid circular dependency
        const { runDiscovery, runGraphBuild } = await import('../../pipeline.js');
        const { runAnalysis } = await import('../../analyzers/engine.js');
        const discovery = await runDiscovery(resolvedPath);
        const graph = runGraphBuild(resolvedPath, discovery);
        const findings = runAnalysis(graph);
        staticContext = buildStaticContext(graph, findings);
        spinner.stop();
        console.log(chalk.green(`  Static scan complete: ${findings.length} findings, ${graph.tools.length} tools detected`));
      } catch (err) {
        spinner.stop();
        console.log(chalk.yellow('  Static scan failed, falling back to full payload set'));
        if (!options.json) {
          console.error(chalk.dim(`  ${err instanceof Error ? err.message : err}`));
        }
      }
    }

    // Verbose logging callback
    const onVerboseLog = options.verbose
      ? (payloadId: string, phase: VerbosePhase, detail: string) => {
          const prefix = phase === 'send' ? chalk.cyan('\u2192')
            : phase === 'receive' ? chalk.yellow('\u2190')
            : chalk.magenta('\u26a1');
          console.log(`${prefix} ${chalk.bold(payloadId)}: ${detail}`);
        }
      : undefined;

    // Run tests
    const spinner = createSpinner('Running adversarial tests...');
    let completed = 0;

    if (!options.json && !options.verbose) {
      spinner.start();
    }

    try {
      const result = await runTests({
        target,
        categories,
        payloadIds,
        mutators,
        staticContext,
        aiProvider,
        timeout: timeoutMs,
        verbose: options.verbose,
        onVerboseLog,
        onProgress: (done, total) => {
          completed = done;
          if (!options.json && !options.verbose) {
            spinner.text = `Running adversarial tests... (${done}/${total})`;
          }
        },
      });

      if (!options.json && !options.verbose) {
        spinner.stop();
      }

      // Output
      if (options.json) {
        const json = reportTestJson(result, options.output);
        if (!options.output) {
          console.log(json);
        } else {
          console.log(`Test results written to: ${options.output}`);
        }
      } else {
        reportTestTerminal(result);
        if (options.output) {
          reportTestJson(result, options.output);
        }
      }

      // Exit code: 1 if any critical vulnerability
      if (result.summary.overallStatus === 'fail') {
        process.exit(1);
      }
    } catch (error) {
      if (!options.json && !options.verbose) {
        spinner.stop();
      }
      console.error(chalk.red('Test execution failed:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

function collectHeaders(value: string, previous: Record<string, string>): Record<string, string> {
  const [key, ...rest] = value.split(':');
  if (key && rest.length > 0) {
    previous[key.trim()] = rest.join(':').trim();
  }
  return previous;
}
