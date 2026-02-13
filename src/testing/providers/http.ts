import type { TestProvider, TestTarget, ConversationMessage } from '../../types/test.js';

const RESPONSE_FIELD_CANDIDATES = [
  'response', 'content', 'message', 'output', 'text', 'result', 'answer', 'reply',
];

const RETRYABLE_STATUS_CODES = new Set([429, 502, 503, 504]);
const MAX_RETRIES = 2;
const RETRY_DELAYS = [1000, 3000];

export function createHttpProvider(target: TestTarget): TestProvider {
  const messageField = target.messageField ?? 'message';
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...target.headers,
  };

  // Conversation history for stateful multi-turn
  const conversationHistory: Array<{ role: string; content: string }> = [];

  async function fetchWithRetry(url: string, init: RequestInit): Promise<Response> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30_000);

      let response: Response;
      try {
        response = await fetch(url, { ...init, signal: controller.signal });
      } catch (err) {
        clearTimeout(timeoutId);
        lastError = err instanceof Error ? err : new Error(String(err));
        if (lastError.name === 'AbortError') {
          throw new Error('Request timed out after 30s');
        }
        // Retry network errors
        if (attempt < MAX_RETRIES) {
          await sleep(RETRY_DELAYS[attempt]);
          continue;
        }
        throw lastError;
      } finally {
        clearTimeout(timeoutId);
      }

      if (response.ok) {
        return response;
      }

      if (RETRYABLE_STATUS_CODES.has(response.status) && attempt < MAX_RETRIES) {
        const retryAfter = response.headers.get('Retry-After');
        const parsed = retryAfter ? parseInt(retryAfter, 10) : NaN;
        const delayMs = Number.isNaN(parsed)
          ? RETRY_DELAYS[attempt]
          : Math.max(Math.min(parsed * 1000, 10_000), 100);
        await sleep(delayMs);
        continue;
      }

      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    throw lastError ?? new Error('Request failed after retries');
  }

  async function sendSingle(message: string): Promise<string> {
    let body: Record<string, unknown>;

    if (target.openai) {
      // OpenAI chat completions format
      const messages: Array<{ role: string; content: string }> = [];
      if (target.systemPrompt) {
        messages.push({ role: 'system', content: target.systemPrompt });
      }
      messages.push({ role: 'user', content: message });

      body = {
        model: target.model ?? 'gpt-4',
        messages,
      };
    } else {
      body = { [messageField]: message };
    }

    const response = await fetchWithRetry(target.endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    const data = await response.json() as Record<string, unknown>;
    return extractResponse(data, target.responseField, target.openai);
  }

  return {
    name: target.name ?? target.endpoint,
    type: 'http',

    async send(message: string): Promise<string> {
      return sendSingle(message);
    },

    async sendConversation(messages: ConversationMessage[]): Promise<string[]> {
      const responses: string[] = [];
      // Reset history for each conversation
      conversationHistory.length = 0;

      for (const msg of messages) {
        if (msg.delayMs) {
          await sleep(msg.delayMs);
        }

        let body: Record<string, unknown>;

        if (target.openai) {
          // OpenAI mode: accumulate full message history
          const apiMessages: Array<{ role: string; content: string }> = [];
          if (target.systemPrompt) {
            apiMessages.push({ role: 'system', content: target.systemPrompt });
          }
          // Add prior history
          for (const h of conversationHistory) {
            apiMessages.push(h);
          }
          // Add current message
          apiMessages.push({ role: msg.role === 'system' ? 'system' : 'user', content: msg.content });

          body = {
            model: target.model ?? 'gpt-4',
            messages: apiMessages,
          };
        } else {
          // Plain HTTP: send message + history array
          body = {
            [messageField]: msg.content,
            ...(conversationHistory.length > 0 ? { history: [...conversationHistory] } : {}),
          };
        }

        const response = await fetchWithRetry(target.endpoint, {
          method: 'POST',
          headers,
          body: JSON.stringify(body),
        });

        const data = await response.json() as Record<string, unknown>;
        const resp = extractResponse(data, target.responseField, target.openai);
        responses.push(resp);

        // Update conversation history
        conversationHistory.push({ role: 'user', content: msg.content });
        conversationHistory.push({ role: 'assistant', content: resp });
      }

      return responses;
    },

    async close(): Promise<void> {
      conversationHistory.length = 0;
    },
  };
}

function extractResponse(data: Record<string, unknown>, responseField?: string, openai?: boolean): string {
  // If user specified a response field, use it
  if (responseField) {
    const value = getNestedValue(data, responseField);
    if (value !== undefined) return String(value);
  }

  // OpenAI mode: check choices first
  if (openai) {
    const choices = data.choices as Array<{ message?: { content?: string } }> | undefined;
    if (choices?.[0]?.message?.content) {
      return choices[0].message.content;
    }
  }

  // Auto-detect: try common field names
  for (const field of RESPONSE_FIELD_CANDIDATES) {
    if (data[field] !== undefined && data[field] !== null) {
      return String(data[field]);
    }
  }

  // Try OpenAI-style nested path (fallback for non-openai mode)
  if (!openai) {
    const choices = data.choices as Array<{ message?: { content?: string } }> | undefined;
    if (choices?.[0]?.message?.content) {
      return choices[0].message.content;
    }
  }

  // Fallback: stringify entire response
  return JSON.stringify(data);
}

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = obj;
  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    // Handle array indexing like "choices[0]"
    const arrayMatch = part.match(/^(\w+)\[(\d+)\]$/);
    if (arrayMatch) {
      const arr = (current as Record<string, unknown>)[arrayMatch[1]];
      if (Array.isArray(arr)) {
        current = arr[parseInt(arrayMatch[2], 10)];
      } else {
        return undefined;
      }
    } else {
      current = (current as Record<string, unknown>)[part];
    }
  }
  return current;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
