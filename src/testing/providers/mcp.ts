import { spawn, type ChildProcess } from 'node:child_process';
import type { TestProvider, TestTarget, ConversationMessage } from '../../types/test.js';

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: number;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id?: number;
  result?: unknown;
  error?: { code: number; message: string };
}

interface MCPTool {
  name: string;
  description?: string;
  inputSchema?: {
    type: string;
    properties?: Record<string, { type: string; description?: string }>;
    required?: string[];
  };
}

export function createMcpProvider(target: TestTarget): TestProvider {
  let process: ChildProcess | null = null;
  let requestId = 0;
  let buffer = '';
  let stderrBuffer = '';
  let initialized = false;
  let tools: MCPTool[] = [];
  const requestTimeout = target.timeout ?? 30_000;

  const pendingResponses = new Map<number, {
    resolve: (value: JsonRpcResponse) => void;
    reject: (reason: Error) => void;
  }>();

  function startProcess(): ChildProcess {
    const args = target.args ?? [];
    const child = spawn(target.endpoint, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    child.stdout!.on('data', (chunk: Buffer) => {
      buffer += chunk.toString();
      processBuffer();
    });

    child.stderr!.on('data', (chunk: Buffer) => {
      stderrBuffer += chunk.toString();
    });

    child.on('error', (err) => {
      const message = (err as NodeJS.ErrnoException).code === 'ENOENT'
        ? `MCP server binary not found: ${target.endpoint}`
        : err.message;
      for (const [, pending] of pendingResponses) {
        pending.reject(new Error(message));
      }
      pendingResponses.clear();
    });

    child.on('exit', () => {
      for (const [, pending] of pendingResponses) {
        const errorDetail = stderrBuffer.trim()
          ? `MCP server process exited. stderr: ${stderrBuffer.trim().slice(0, 500)}`
          : 'MCP server process exited';
        pending.reject(new Error(errorDetail));
      }
      pendingResponses.clear();
    });

    return child;
  }

  function processBuffer(): void {
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const msg = JSON.parse(trimmed) as JsonRpcResponse;
        // Skip JSON-RPC notifications (messages without an id field)
        if (msg.id === undefined || msg.id === null) continue;
        if (pendingResponses.has(msg.id)) {
          const pending = pendingResponses.get(msg.id)!;
          pendingResponses.delete(msg.id);
          pending.resolve(msg);
        }
      } catch {
        // Non-JSON line, ignore
      }
    }
  }

  function sendRequest(method: string, params?: Record<string, unknown>): Promise<JsonRpcResponse> {
    const id = ++requestId;
    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      id,
      method,
      ...(params ? { params } : {}),
    };

    return new Promise<JsonRpcResponse>((resolve, reject) => {
      const timeout = setTimeout(() => {
        pendingResponses.delete(id);
        const stderrHint = stderrBuffer.trim()
          ? ` (stderr: ${stderrBuffer.trim().slice(0, 200)})`
          : '';
        reject(new Error(`MCP request timeout: ${method}${stderrHint}`));
      }, requestTimeout);

      pendingResponses.set(id, {
        resolve: (resp) => {
          clearTimeout(timeout);
          resolve(resp);
        },
        reject: (err) => {
          clearTimeout(timeout);
          reject(err);
        },
      });

      process!.stdin!.write(JSON.stringify(request) + '\n');
    });
  }

  async function ensureInitialized(): Promise<void> {
    if (initialized) return;

    if (!process) {
      process = startProcess();
    }

    // Send initialize
    await sendRequest('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'g0-test', version: '1.0.0' },
    });

    // Send initialized notification (no response expected)
    process!.stdin!.write(JSON.stringify({
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    }) + '\n');

    // Get available tools
    const toolsResp = await sendRequest('tools/list');
    if (toolsResp.result && typeof toolsResp.result === 'object') {
      const result = toolsResp.result as { tools?: MCPTool[] };
      tools = result.tools ?? [];
    }

    initialized = true;
  }

  function findTargetTool(message: string): { tool: MCPTool; args: Record<string, string> } | null {
    // Find the first tool that accepts a string parameter
    for (const tool of tools) {
      const props = tool.inputSchema?.properties;
      if (!props) continue;

      for (const [paramName, paramDef] of Object.entries(props)) {
        if (paramDef.type === 'string') {
          return { tool, args: { [paramName]: message } };
        }
      }
    }

    // Fallback: use first tool with any parameter
    if (tools.length > 0 && tools[0].inputSchema?.properties) {
      const firstParam = Object.keys(tools[0].inputSchema.properties)[0];
      if (firstParam) {
        return { tool: tools[0], args: { [firstParam]: message } };
      }
    }

    return null;
  }

  async function sendSingle(message: string): Promise<string> {
    await ensureInitialized();

    const targetTool = findTargetTool(message);
    if (!targetTool) {
      return '[No suitable MCP tool found to accept input]';
    }

    const resp = await sendRequest('tools/call', {
      name: targetTool.tool.name,
      arguments: targetTool.args,
    });

    if (resp.error) {
      return `[MCP Error: ${resp.error.message}]`;
    }

    // Extract text from tool result
    const result = resp.result as { content?: Array<{ type: string; text?: string }> } | undefined;
    if (result?.content) {
      return result.content
        .filter(c => c.type === 'text' && c.text)
        .map(c => c.text!)
        .join('\n') || JSON.stringify(result);
    }

    return JSON.stringify(resp.result ?? '');
  }

  return {
    name: target.name ?? `mcp:${target.endpoint}`,
    type: 'mcp-stdio',

    async send(message: string): Promise<string> {
      return sendSingle(message);
    },

    async sendConversation(messages: ConversationMessage[]): Promise<string[]> {
      const responses: string[] = [];
      for (const msg of messages) {
        if (msg.delayMs) {
          await new Promise(resolve => setTimeout(resolve, msg.delayMs));
        }
        const resp = await sendSingle(msg.content);
        responses.push(resp);
      }
      return responses;
    },

    async close(): Promise<void> {
      if (process) {
        process.kill('SIGTERM');
        process = null;
      }
      initialized = false;
      tools = [];
      buffer = '';
      stderrBuffer = '';
      pendingResponses.clear();
    },
  };
}
