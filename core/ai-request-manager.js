/* ============================================================
   CORSAIR UNBOUND — AI REQUEST MANAGER (v1.13.0)
   ------------------------------------------------------------
   Executes provider requests inside the trusted service worker.
   - Timeout & external AbortController cancellation
   - SSE & NDJSON streaming + non-streaming response handling
   - Verifies usable payload (never treats bare HTTP 200 as ok)
   - Redacts API keys from all errors and diagnostics
   - NEVER silently falls back from local to cloud providers
   ============================================================ */

const CorsairAIRequestManager = (() => {
  'use strict';

  const _activeRequests = new Map();

  function getProviders() {
    if (typeof CorsairAIProviders === 'undefined') {
      throw new Error('CorsairAIProviders is not loaded.');
    }
    return CorsairAIProviders;
  }

  function safeError(err, apiKey) {
    const P = getProviders();
    const raw = (err && err.message) ? err.message : String(err || 'Unknown request error');
    return P.redactSecret(raw, apiKey);
  }

  function cancelRequest(requestId) {
    const entry = _activeRequests.get(requestId);
    if (!entry) return false;
    try { entry.controller.abort(new Error('Cancelled by user')); } catch {}
    _activeRequests.delete(requestId);
    return true;
  }

  async function fetchWithTimeout(url, init, timeoutMs, requestId) {
    const controller = new AbortController();
    if (requestId) _activeRequests.set(requestId, { controller, startedAt: Date.now() });
    const ms = Math.max(2000, Math.min(300000, Number(timeoutMs) || 60000));
    const timer = setTimeout(() => {
      try { controller.abort(new Error(`Request timed out after ${ms}ms`)); } catch {}
    }, ms);
    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
      if (requestId) _activeRequests.delete(requestId);
    }
  }

  async function readErrorBody(res, apiKey) {
    const P = getProviders();
    try {
      const text = await res.text();
      if (!text) return `HTTP ${res.status} ${res.statusText || ''}`.trim();
      try {
        const j = JSON.parse(text);
        const msg = j?.error?.message || (typeof j?.error === 'string' ? j.error : '') || j?.message || text.slice(0, 240);
        return P.redactSecret(`HTTP ${res.status}: ${msg}`, apiKey);
      } catch {
        return P.redactSecret(`HTTP ${res.status}: ${text.slice(0, 240)}`, apiKey);
      }
    } catch {
      return `HTTP ${res.status}`;
    }
  }

  async function consumeStream(res, adapter, streamFormat, onChunk, apiKey) {
    const reader = res.body && typeof res.body.getReader === 'function' ? res.body.getReader() : null;
    if (!reader) {
      // Fallback if mock or server returned non-streamable body
      const text = await res.text();
      const json = JSON.parse(text);
      const parsed = adapter.parseChatResponse(json);
      if (!parsed.ok) throw new Error(parsed.error);
      if (onChunk && parsed.text) onChunk(parsed.text);
      return parsed;
    }

    const decoder = new TextDecoder('utf-8');
    let buffer = '';
    let fullText = '';
    let finishReason = '';

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || '';

      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;
        try {
          if (streamFormat === 'sse') {
            if (!line.startsWith('data:')) continue;
            const payload = line.slice(5).trim();
            if (!payload) continue;
            const chunk = adapter.parseStreamChunk(payload);
            if (chunk.text) {
              fullText += chunk.text;
              if (onChunk) onChunk(chunk.text);
            }
            if (chunk.finishReason) finishReason = chunk.finishReason;
            if (chunk.done) return { ok: true, text: fullText, finishReason };
          } else {
            const chunk = adapter.parseStreamChunk(line);
            if (chunk.text) {
              fullText += chunk.text;
              if (onChunk) onChunk(chunk.text);
            }
            if (chunk.done) return { ok: true, text: fullText, finishReason: 'stop' };
          }
        } catch (e) {
          throw new Error(safeError(e, apiKey));
        }
      }
    }

    if (!fullText.trim()) {
      return { ok: false, error: 'Stream ended without usable assistant text.' };
    }
    return { ok: true, text: fullText, finishReason };
  }

  /**
   * Execute a chat completion request against a single explicitly chosen provider profile.
   * Never silently switches to another provider on failure.
   */
  async function generate({ profile, apiKey, messages, model, temperature, maxTokens, stream, timeoutMs, requestId, onChunk }) {
    const P = getProviders();
    if (!profile) return { ok: false, error: 'No AI provider profile selected.' };

    const urlCheck = P.validateBaseUrl(profile.baseUrl);
    if (!urlCheck.ok) return { ok: false, error: urlCheck.error };

    const resolvedKey = apiKey !== undefined ? String(apiKey || '') : await P.getApiKey(profile.id);
    if (profile.requiresKey && !resolvedKey) {
      return { ok: false, code: 'missing-api-key', error: `API key required for ${profile.name}.` };
    }

    const adapter = P.getAdapter(profile);
    const useStream = Boolean(stream && profile.supportsStreaming !== false);
    const req = adapter.buildChatRequest(profile, {
      messages,
      model: model || profile.model || profile.defaultModel,
      temperature,
      maxTokens,
      stream: useStream
    }, resolvedKey);

    const startedAt = Date.now();
    try {
      const res = await fetchWithTimeout(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.body
      }, timeoutMs || profile.timeoutMs || 60000, requestId);

      if (!res.ok) {
        const errMsg = await readErrorBody(res, resolvedKey);
        const code = res.status === 401 || res.status === 403 ? 'auth-failed' : 'http-error';
        return { ok: false, code, status: res.status, error: errMsg, latencyMs: Date.now() - startedAt };
      }

      const contentType = (res.headers && res.headers.get && res.headers.get('content-type')) || '';
      if (useStream && (contentType.includes('text/event-stream') || contentType.includes('ndjson') || req.streamFormat === 'ndjson')) {
        const streamed = await consumeStream(res, adapter, req.streamFormat, onChunk, resolvedKey);
        return { ...streamed, latencyMs: Date.now() - startedAt, providerId: profile.id, locality: urlCheck.locality };
      }

      const rawText = await res.text();
      let json;
      try {
        json = JSON.parse(rawText);
      } catch {
        return {
          ok: false,
          code: 'invalid-response',
          error: 'Provider returned non-JSON content (check endpoint URL and server mode).',
          latencyMs: Date.now() - startedAt
        };
      }
      const parsed = adapter.parseChatResponse(json);
      if (!parsed.ok) {
        return { ok: false, code: 'invalid-response', error: P.redactSecret(parsed.error, resolvedKey), latencyMs: Date.now() - startedAt };
      }
      return { ...parsed, latencyMs: Date.now() - startedAt, providerId: profile.id, locality: urlCheck.locality };
    } catch (err) {
      const isAbort = err && (err.name === 'AbortError' || /abort|timed out|cancelled/i.test(String(err.message || '')));
      return {
        ok: false,
        code: isAbort ? 'aborted' : 'network-error',
        error: safeError(err, resolvedKey),
        latencyMs: Date.now() - startedAt
      };
    }
  }

  /**
   * Optional model discovery. Returns ok:true with models array, or graceful unsupported/error detail.
   */
  async function fetchModels({ profile, apiKey, timeoutMs }) {
    const P = getProviders();
    if (!profile) return { ok: false, models: [], error: 'No provider profile.' };
    if (profile.supportsDiscovery === false) {
      return { ok: false, unsupported: true, models: [], error: 'Model discovery is disabled for this profile. Enter model ID manually.' };
    }
    const urlCheck = P.validateBaseUrl(profile.baseUrl);
    if (!urlCheck.ok) return { ok: false, models: [], error: urlCheck.error };

    const resolvedKey = apiKey !== undefined ? String(apiKey || '') : await P.getApiKey(profile.id);
    if (profile.requiresKey && !resolvedKey) {
      return { ok: false, code: 'missing-api-key', models: [], error: `API key required for ${profile.name}.` };
    }

    const adapter = P.getAdapter(profile);
    const req = adapter.buildModelsRequest(profile, resolvedKey);
    try {
      const res = await fetchWithTimeout(req.url, { method: req.method, headers: req.headers }, timeoutMs || 15000);
      if (res.status === 404 || res.status === 405) {
        return { ok: false, unsupported: true, status: res.status, models: [], error: 'Provider does not expose a models discovery endpoint. Enter model ID manually.' };
      }
      if (!res.ok) {
        return {
          ok: false,
          code: res.status === 401 || res.status === 403 ? 'auth-failed' : 'http-error',
          status: res.status,
          models: [],
          error: await readErrorBody(res, resolvedKey)
        };
      }
      const rawText = await res.text();
      let json;
      try { json = JSON.parse(rawText); }
      catch { return { ok: false, code: 'invalid-response', models: [], error: 'Models endpoint returned non-JSON payload.' }; }
      const parsed = adapter.parseModelsResponse(json);
      if (!parsed.ok) return { ok: false, code: 'invalid-response', models: [], error: parsed.error };
      return { ok: true, models: parsed.models };
    } catch (err) {
      return { ok: false, code: 'network-error', models: [], error: safeError(err, resolvedKey) };
    }
  }

  /**
   * Connection test: verifies actual usable API response (never passes on bare HTTP 200 HTML).
   */
  async function testConnection({ profile, apiKey }) {
    const startedAt = Date.now();
    const discovered = await fetchModels({ profile, apiKey, timeoutMs: 12000 });
    if (discovered.ok) {
      return {
        ok: true,
        method: 'models',
        modelCount: discovered.models.length,
        models: discovered.models,
        latencyMs: Date.now() - startedAt,
        message: `Connected (${discovered.models.length} model${discovered.models.length === 1 ? '' : 's'} discovered).`
      };
    }
    if (discovered.unsupported) {
      // Fall back to a minimal generation probe when discovery endpoint is not supported
      const probe = await testGeneration({ profile, apiKey });
      return {
        ok: probe.ok,
        method: 'generation-probe',
        latencyMs: Date.now() - startedAt,
        error: probe.error,
        message: probe.ok ? 'Connected (verified via minimal generation probe).' : probe.error
      };
    }
    return {
      ok: false,
      code: discovered.code || 'connection-failed',
      latencyMs: Date.now() - startedAt,
      error: discovered.error || 'Connection test failed.'
    };
  }

  async function testGeneration({ profile, apiKey }) {
    const res = await generate({
      profile,
      apiKey,
      messages: [
        { role: 'system', content: 'Respond with exactly: OK' },
        { role: 'user', content: 'Ping' }
      ],
      temperature: 0,
      maxTokens: 16,
      stream: false,
      timeoutMs: Math.min(20000, profile?.timeoutMs || 20000)
    });
    if (!res.ok) return res;
    if (!String(res.text || '').trim()) {
      return { ok: false, code: 'empty-response', error: 'Model returned an empty response.' };
    }
    return { ok: true, sample: res.text.trim().slice(0, 80), latencyMs: res.latencyMs };
  }

  return {
    generate,
    fetchModels,
    testConnection,
    testGeneration,
    cancelRequest
  };
})();

globalThis.CorsairAIRequestManager = CorsairAIRequestManager;
