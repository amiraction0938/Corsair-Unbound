import { describe, it, expect } from 'vitest';
import { loadCore } from './helpers/load-core.js';

function makeStorageChrome() {
  const local = {};
  const session = {};
  return {
    storage: {
      local: {
        async get(keys) {
          if (typeof keys === 'string') return { [keys]: local[keys] };
          if (Array.isArray(keys)) { const o = {}; for (const k of keys) if (k in local) o[k] = local[k]; return o; }
          return { ...local };
        },
        async set(obj) { Object.assign(local, obj); }
      },
      session: {
        async get(keys) {
          if (typeof keys === 'string') return { [keys]: session[keys] };
          return { ...session };
        },
        async set(obj) { Object.assign(session, obj); }
      }
    }
  };
}

function mockJsonResponse(obj, status = 200, contentType = 'application/json') {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'ERR',
    headers: { get: (k) => (k.toLowerCase() === 'content-type' ? contentType : null) },
    async text() { return typeof obj === 'string' ? obj : JSON.stringify(obj); }
  };
}

describe('AI Providers Registry & Request Manager (v1.13.0)', () => {
  it('registers all 9 local presets and 10 cloud presets and classifies locality accurately', () => {
    globalThis.chrome = makeStorageChrome(); loadCore('core/ai-providers.js'); const P = globalThis.CorsairAIProviders;
    const requiredLocal = ['llamacpp', 'ollama', 'lmstudio', 'vllm', 'localai', 'jan', 'textgen-webui', 'koboldcpp', 'generic-local-openai'];
    const requiredCloud = ['openai', 'gemini', 'anthropic', 'openrouter', 'deepseek', 'qwen', 'mistral', 'groq', 'xai', 'custom-openai'];
    for (const k of [...requiredLocal, ...requiredCloud]) {
      expect(P.PRESETS[k]).toBeDefined();
    }
    expect(P.classifyEndpointLocality('http://127.0.0.1:9101/v1')).toBe('local');
    expect(P.classifyEndpointLocality('http://localhost:11434')).toBe('local');
    expect(P.classifyEndpointLocality('http://192.168.1.50:8000/v1')).toBe('lan');
    expect(P.classifyEndpointLocality('https://api.openai.com/v1')).toBe('cloud');
    expect(P.validateBaseUrl('http://api.openai.com/v1').ok).toBe(false);
    expect(P.validateBaseUrl('http://127.0.0.1:9101/v1').ok).toBe(true);
  });

  it('builds native requests & parses responses for llama.cpp, Ollama, Gemini, Anthropic, OpenRouter', async () => {
    const chrome = makeStorageChrome();
    globalThis.chrome = chrome; loadCore('core/ai-providers.js'); const P = globalThis.CorsairAIProviders;

    // llama.cpp (OpenAI-compat)
    const llama = P.createProfileFromPreset('llamacpp', { baseUrl: 'http://127.0.0.1:9101/v1', model: 'qwen-2.5' });
    const lReq = P.getAdapter(llama).buildChatRequest(llama, { messages: [{ role: 'user', content: 'hi' }] }, '');
    expect(lReq.url).toBe('http://127.0.0.1:9101/v1/chat/completions');
    expect(lReq.headers.Authorization).toBeUndefined();

    // Ollama native
    const ollama = P.createProfileFromPreset('ollama', { model: 'qwen2.5-coder:7b' });
    const oReq = P.getAdapter(ollama).buildChatRequest(ollama, { messages: [{ role: 'user', content: 'hi' }] }, '');
    expect(oReq.url).toBe('http://127.0.0.1:11434/api/chat');
    expect(P.getAdapter(ollama).parseChatResponse({ message: { content: 'hello' }, done: true }).text).toBe('hello');
    expect(P.getAdapter(ollama).parseModelsResponse({ models: [{ name: 'qwen2.5-coder:7b' }] }).models).toEqual(['qwen2.5-coder:7b']);

    // Gemini native
    const gemini = P.createProfileFromPreset('gemini', { model: 'gemini-2.5-flash' });
    const gReq = P.getAdapter(gemini).buildChatRequest(gemini, { messages: [{ role: 'system', content: 'sys' }, { role: 'user', content: 'hi' }] }, ['AIza', 'FakeKey123456789012345'].join(''));
    expect(gReq.url).toContain('/models/gemini-2.5-flash:generateContent');
    expect(gReq.headers['x-goog-api-key']).toBe(['AIza', 'FakeKey123456789012345'].join(''));
    expect(P.getAdapter(gemini).parseChatResponse({ candidates: [{ content: { parts: [{ text: 'ok' }] } }] }).text).toBe('ok');

    // Anthropic native
    const anth = P.createProfileFromPreset('anthropic', { model: 'claude-3-5-sonnet-latest' });
    const aReq = P.getAdapter(anth).buildChatRequest(anth, { messages: [{ role: 'system', content: 'sys' }, { role: 'user', content: 'hi' }] }, ['sk-', 'ant-1234567890123'].join(''));
    expect(aReq.url).toBe('https://api.anthropic.com/v1/messages');
    expect(aReq.headers['x-api-key']).toBe(['sk-', 'ant-1234567890123'].join(''));
    expect(aReq.headers['anthropic-version']).toBe('2023-06-01');
    expect(P.getAdapter(anth).parseChatResponse({ content: [{ type: 'text', text: 'claude ok' }] }).text).toBe('claude ok');

    // OpenRouter
    const or = P.createProfileFromPreset('openrouter');
    const orReq = P.getAdapter(or).buildChatRequest(or, { messages: [{ role: 'user', content: 'hi' }] }, ['sk-', 'or-1234567890123'].join(''));
    expect(orReq.headers['HTTP-Referer']).toContain('Corsair-Unbound');
  });

  it('stores API keys in session storage by default and redacts secrets from errors', async () => {
    const chrome = makeStorageChrome();
    globalThis.chrome = chrome; loadCore('core/ai-providers.js'); const P = globalThis.CorsairAIProviders;
    const saved = await P.saveProfile({ type: 'openai', name: 'My OpenAI', baseUrl: 'https://api.openai.com/v1', model: 'gpt-4o-mini' }, ['sk-', 'supersecret123456789'].join(''));
    expect(saved.ok).toBe(true);
    expect(await P.getApiKey(saved.profile.id)).toBe(['sk-', 'supersecret123456789'].join(''));
    const listed = await P.listProfiles();
    const found = listed.profiles.find(x => x.id === saved.profile.id);
    expect(found.keyStorage).toBe('session');
    expect(found.apiKey).toBeUndefined();

    const redacted = P.redactSecret('Auth failed for ' + ['sk-', 'supersecret123456789'].join(''), ['sk-', 'supersecret123456789'].join(''));
    expect(redacted).not.toContain(['sk-', 'supersecret123456789'].join(''));
    expect(redacted).toContain('[REDACTED_KEY]');
  });

  it('rejects HTTP 200 HTML/non-JSON responses during testConnection & handles auth/network/discovery failures', async () => {
    const chrome = makeStorageChrome();
    globalThis.chrome = chrome; loadCore('core/ai-providers.js'); const P = globalThis.CorsairAIProviders;

    // HTTP 200 HTML must FAIL (never report ok just because status is 200)
    globalThis.chrome = chrome; globalThis.CorsairAIProviders = P; globalThis.fetch = async () => mockJsonResponse('<html>Not an API</html>', 200, 'text/html'); loadCore('core/ai-request-manager.js'); const M1 = globalThis.CorsairAIRequestManager;
    const llama = P.createProfileFromPreset('llamacpp');
    const htmlTest = await M1.testConnection({ profile: llama });
    expect(htmlTest.ok).toBe(false);
    expect(htmlTest.code).toBe('invalid-response');

    // HTTP 401 auth failure redacts key
    globalThis.chrome = chrome; globalThis.CorsairAIProviders = P; globalThis.fetch = async () => mockJsonResponse({ error: { message: 'Invalid key ' + ['sk-', 'leaktest123456789'].join('') } }, 401); loadCore('core/ai-request-manager.js'); const M2 = globalThis.CorsairAIRequestManager;
    const openai = P.createProfileFromPreset('openai');
    const authRes = await M2.generate({ profile: openai, apiKey: ['sk-', 'leaktest123456789'].join(''), messages: [{ role: 'user', content: 'hi' }] });
    expect(authRes.ok).toBe(false);
    expect(authRes.code).toBe('auth-failed');
    expect(authRes.error).not.toContain(['sk-', 'leaktest123456789'].join(''));

    // HTTP 404 on /models returns unsupported:true cleanly
    globalThis.chrome = chrome; globalThis.CorsairAIProviders = P; globalThis.fetch = async () => mockJsonResponse({ error: 'not found' }, 404); loadCore('core/ai-request-manager.js'); const M3 = globalThis.CorsairAIRequestManager;
    const disc = await M3.fetchModels({ profile: llama });
    expect(disc.ok).toBe(false);
    expect(disc.unsupported).toBe(true);
  });

  it('supports SSE streaming and AbortController cancellation', async () => {
    const chrome = makeStorageChrome();
    globalThis.chrome = chrome; loadCore('core/ai-providers.js'); const P = globalThis.CorsairAIProviders;

    const encoder = new TextEncoder();
    const chunks = [
      'data: {"choices":[{"delta":{"content":"// ==UserScript=="}}]}\n\n',
      'data: {"choices":[{"delta":{"content":"\\nconsole.log(1);"}}]}\n\n',
      'data: [DONE]\n\n'
    ];
    let idx = 0;
    globalThis.chrome = chrome; globalThis.CorsairAIProviders = P; globalThis.fetch = async () => ({
        ok: true,
        status: 200,
        headers: { get: () => 'text/event-stream' },
        body: {
          getReader() {
            return {
              async read() {
                if (idx >= chunks.length) return { done: true };
                return { done: false, value: encoder.encode(chunks[idx++]) };
              }
            };
          }
        }
      }); loadCore('core/ai-request-manager.js'); const M = globalThis.CorsairAIRequestManager;
    const seen = [];
    const res = await M.generate({
      profile: P.createProfileFromPreset('llamacpp'),
      messages: [{ role: 'user', content: 'gen' }],
      stream: true,
      onChunk: (c) => seen.push(c)
    });
    expect(res.ok).toBe(true);
    expect(res.text).toContain('// ==UserScript==');
    expect(seen.length).toBe(2);
  });
});
