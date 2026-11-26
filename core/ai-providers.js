/* ============================================================
   CORSAIR UNBOUND — AI PROVIDERS & ADAPTER REGISTRY (v1.13.0)
   ------------------------------------------------------------
   First-class local LLM & multi-cloud provider management.
   - Local presets: llama.cpp, Ollama (native + OpenAI-compat),
     LM Studio, vLLM, LocalAI, Jan, Text Generation WebUI,
     KoboldCpp, Generic Local OpenAI-Compatible.
   - Cloud presets: OpenAI, Google Gemini, Anthropic, OpenRouter,
     DeepSeek, Alibaba Qwen / DashScope, Mistral, Groq, xAI,
     Custom OpenAI-Compatible.
   - Session-storage-first secret handling (survives SW restarts,
     clears when browser closes), with explicit opt-in persistent
     storage and clear security disclosure.
   - Zero silent local -> cloud fallback.
   ============================================================ */

const CorsairAIProviders = (() => {
  'use strict';

  const PROFILES_KEY = 'cai:profiles';
  const DEFAULT_PROFILE_KEY = 'cai:defaultProfileId';
  const SESSION_KEYS_KEY = 'cai:sessionKeys';
  const PERSIST_KEYS_KEY = 'cai:persistKeys';

  /* ============================================================
     LOCALITY & URL CLASSIFICATION
     ============================================================ */
  function extractHost(baseUrl) {
    try {
      const u = new URL(String(baseUrl || '').trim());
      return (u.hostname || '').toLowerCase();
    } catch {
      return '';
    }
  }

  function classifyEndpointLocality(baseUrl) {
    const host = extractHost(baseUrl);
    if (!host) return 'invalid';
    if (
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '::1' ||
      host === '[::1]' ||
      host.startsWith('127.')
    ) {
      return 'local';
    }
    if (
      host.startsWith('10.') ||
      host.startsWith('192.168.') ||
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(host) ||
      host.endsWith('.local') ||
      host.endsWith('.lan') ||
      host.endsWith('.home') ||
      host.endsWith('.internal')
    ) {
      return 'lan';
    }
    return 'cloud';
  }

  function normalizeBaseUrl(url) {
    return String(url || '').trim().replace(/\/+$/, '');
  }

  function validateBaseUrl(url) {
    const cleaned = normalizeBaseUrl(url);
    if (!cleaned) return { ok: false, error: 'Base URL is required.' };
    try {
      const u = new URL(cleaned);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return { ok: false, error: 'Base URL must use http:// or https://.' };
      }
      const locality = classifyEndpointLocality(cleaned);
      if (locality === 'cloud' && u.protocol !== 'https:') {
        return { ok: false, error: 'Remote cloud providers must use HTTPS.' };
      }
      return { ok: true, url: cleaned, locality };
    } catch {
      return { ok: false, error: 'Invalid Base URL format.' };
    }
  }

  /* ============================================================
     PROVIDER PRESETS (LOCAL FIRST)
     ============================================================ */
  const PRESETS = {
    // --- LOCAL PROVIDERS ---
    llamacpp: {
      type: 'llamacpp',
      suggestedModels: ["local-model", "qwen2.5-coder-7b-instruct", "qwen2.5-coder-14b-instruct", "qwen2.5-coder-32b-instruct", "gemma-3-12b-it", "llama-3.1-8b-instruct", "deepseek-coder-v2-lite-instruct"],
      name: 'llama.cpp Server',
      category: 'local',
      adapter: 'openai-compat',
      baseUrl: 'http://127.0.0.1:9101/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'none',
      requiresKey: false,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: 'local-model',
      notes: 'OpenAI-compatible llama-server (port configurable, e.g. 9101 or 8080).'
    },
    ollama: {
      type: 'ollama',
      suggestedModels: ["qwen2.5-coder:7b", "qwen2.5-coder:14b", "qwen2.5-coder:32b", "qwen3:8b", "gemma3:12b", "llama3.2:latest", "llama3.1:8b", "deepseek-r1:8b", "deepseek-coder-v2:16b", "codellama:7b", "mistral:7b"],
      name: 'Ollama (Local)',
      category: 'local',
      adapter: 'ollama',
      baseUrl: 'http://127.0.0.1:11434',
      chatPath: '/api/chat',
      modelsPath: '/api/tags',
      authMode: 'none',
      requiresKey: false,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: 'qwen2.5-coder:7b',
      notes: 'Native Ollama API (/api/chat & /api/tags). Switch adapter to openai-compat for /v1.'
    },
    lmstudio: {
      type: 'lmstudio',
      suggestedModels: ["qwen2.5-coder-7b-instruct", "qwen2.5-coder-14b-instruct", "gemma-3-12b-it", "deepseek-r1-distill-qwen-7b", "meta-llama-3.1-8b-instruct"],
      name: 'LM Studio',
      category: 'local',
      adapter: 'openai-compat',
      baseUrl: 'http://127.0.0.1:1234/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'none',
      requiresKey: false,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: '',
      notes: 'LM Studio local OpenAI-compatible server.'
    },
    vllm: {
      type: 'vllm',
      suggestedModels: ["Qwen/Qwen2.5-Coder-7B-Instruct", "Qwen/Qwen2.5-Coder-32B-Instruct", "meta-llama/Llama-3.1-8B-Instruct", "deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct"],
      name: 'vLLM',
      category: 'local',
      adapter: 'openai-compat',
      baseUrl: 'http://127.0.0.1:8000/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'none',
      requiresKey: false,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: '',
      notes: 'vLLM OpenAI-compatible serving endpoint.'
    },
    localai: {
      type: 'localai',
      suggestedModels: ["qwen2.5-coder-7b-instruct", "llama-3.1-8b-instruct", "mistral-7b-instruct"],
      name: 'LocalAI',
      category: 'local',
      adapter: 'openai-compat',
      baseUrl: 'http://127.0.0.1:8080/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'none',
      requiresKey: false,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: '',
      notes: 'LocalAI OpenAI-compatible server.'
    },
    jan: {
      type: 'jan',
      suggestedModels: ["qwen2.5-coder-7b-instruct", "llama-3.2-3b-instruct", "mistral-ins-7b-q4"],
      name: 'Jan Local API',
      category: 'local',
      adapter: 'openai-compat',
      baseUrl: 'http://127.0.0.1:1337/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'none',
      requiresKey: false,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: '',
      notes: 'Jan local OpenAI-compatible API server.'
    },
    'textgen-webui': {
      type: 'textgen-webui',
      suggestedModels: ["local-model", "qwen2.5-coder-7b-instruct", "llama-3.1-8b-instruct"],
      name: 'Text Generation WebUI',
      category: 'local',
      adapter: 'openai-compat',
      baseUrl: 'http://127.0.0.1:5000/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'none',
      requiresKey: false,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: '',
      notes: 'Requires --api flag (OpenAI extension) enabled in oobabooga.'
    },
    koboldcpp: {
      type: 'koboldcpp',
      suggestedModels: ["koboldcpp", "qwen2.5-coder-7b-instruct", "llama-3.1-8b-instruct"],
      name: 'KoboldCpp',
      category: 'local',
      adapter: 'openai-compat',
      baseUrl: 'http://127.0.0.1:5001/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'none',
      requiresKey: false,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: 'koboldcpp',
      notes: 'KoboldCpp OpenAI-compatible endpoint (/v1/chat/completions).'
    },
    'generic-local-openai': {
      type: 'generic-local-openai',
      suggestedModels: ["local-model", "qwen2.5-coder:7b", "gemma-3-12b-it", "llama-3.1-8b-instruct"],
      name: 'Generic Local OpenAI-Compatible',
      category: 'local',
      adapter: 'openai-compat',
      baseUrl: 'http://127.0.0.1:8000/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'none',
      requiresKey: false,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: '',
      notes: 'Connect any local or LAN server exposing an OpenAI-compatible API.'
    },

    // --- CLOUD PROVIDERS ---
    openai: {
      type: 'openai',
      suggestedModels: ["gpt-4.1", "gpt-4.1-mini", "gpt-4o", "gpt-4o-mini", "o3-mini", "o4-mini"],
      name: 'OpenAI',
      category: 'cloud',
      adapter: 'openai-compat',
      baseUrl: 'https://api.openai.com/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'bearer',
      requiresKey: true,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: 'gpt-4o-mini',
      notes: 'OpenAI Chat Completions API.'
    },
    gemini: {
      type: 'gemini',
      suggestedModels: ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash", "gemini-2.0-flash-lite"],
      name: 'Google Gemini',
      category: 'cloud',
      adapter: 'gemini',
      baseUrl: 'https://generativelanguage.googleapis.com/v1beta',
      chatPath: '/models/{model}:generateContent',
      modelsPath: '/models',
      authMode: 'x-goog-api-key',
      requiresKey: true,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: 'gemini-2.5-flash',
      notes: 'Native Google Gemini Generative Language API (x-goog-api-key header).'
    },
    anthropic: {
      type: 'anthropic',
      suggestedModels: ["claude-3-7-sonnet-latest", "claude-3-5-sonnet-latest", "claude-3-5-haiku-latest", "claude-3-opus-latest"],
      name: 'Anthropic Claude',
      category: 'cloud',
      adapter: 'anthropic',
      baseUrl: 'https://api.anthropic.com/v1',
      chatPath: '/messages',
      modelsPath: '/models',
      authMode: 'x-api-key',
      requiresKey: true,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: 'claude-3-5-sonnet-latest',
      notes: 'Native Anthropic Messages API (x-api-key + anthropic-version).'
    },
    openrouter: {
      type: 'openrouter',
      suggestedModels: ["qwen/qwen-2.5-coder-32b-instruct", "anthropic/claude-3.7-sonnet", "google/gemini-2.5-flash", "openai/gpt-4.1-mini", "deepseek/deepseek-chat-v3-0324", "meta-llama/llama-3.3-70b-instruct"],
      name: 'OpenRouter',
      category: 'cloud',
      adapter: 'openrouter',
      baseUrl: 'https://openrouter.ai/api/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'bearer',
      requiresKey: true,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: 'qwen/qwen-2.5-coder-32b-instruct',
      notes: 'OpenRouter unified model gateway.'
    },
    deepseek: {
      type: 'deepseek',
      suggestedModels: ["deepseek-chat", "deepseek-reasoner"],
      name: 'DeepSeek',
      category: 'cloud',
      adapter: 'openai-compat',
      baseUrl: 'https://api.deepseek.com/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'bearer',
      requiresKey: true,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: 'deepseek-chat',
      notes: 'DeepSeek OpenAI-compatible API.'
    },
    qwen: {
      type: 'qwen',
      suggestedModels: ["qwen-plus", "qwen-max", "qwen-turbo", "qwen2.5-coder-32b-instruct", "qwen3-coder-plus"],
      name: 'Alibaba Qwen / DashScope',
      category: 'cloud',
      adapter: 'openai-compat',
      baseUrl: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'bearer',
      requiresKey: true,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: 'qwen-plus',
      notes: 'Alibaba Cloud DashScope OpenAI-compatible mode.'
    },
    mistral: {
      type: 'mistral',
      suggestedModels: ["codestral-latest", "mistral-large-latest", "mistral-small-latest", "ministral-8b-latest"],
      name: 'Mistral AI',
      category: 'cloud',
      adapter: 'openai-compat',
      baseUrl: 'https://api.mistral.ai/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'bearer',
      requiresKey: true,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: 'codestral-latest',
      notes: 'Mistral AI Chat Completions API.'
    },
    groq: {
      type: 'groq',
      suggestedModels: ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "qwen-qwq-32b", "mixtral-8x7b-32768"],
      name: 'Groq',
      category: 'cloud',
      adapter: 'openai-compat',
      baseUrl: 'https://api.groq.com/openai/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'bearer',
      requiresKey: true,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: 'llama-3.3-70b-versatile',
      notes: 'Groq OpenAI-compatible inference API.'
    },
    xai: {
      type: 'xai',
      suggestedModels: ["grok-3", "grok-3-mini", "grok-2-latest"],
      name: 'xAI (Grok)',
      category: 'cloud',
      adapter: 'openai-compat',
      baseUrl: 'https://api.x.ai/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'bearer',
      requiresKey: true,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: 'grok-2-latest',
      notes: 'xAI OpenAI-compatible API.'
    },
    'custom-openai': {
      type: 'custom-openai',
      suggestedModels: ["gpt-4o-mini", "qwen2.5-coder-32b-instruct", "local-model"],
      name: 'Custom OpenAI-Compatible',
      category: 'custom',
      adapter: 'openai-compat',
      baseUrl: 'https://api.example.com/v1',
      chatPath: '/chat/completions',
      modelsPath: '/models',
      authMode: 'bearer',
      requiresKey: false,
      supportsDiscovery: true,
      supportsStreaming: true,
      defaultModel: '',
      notes: 'Custom hosted or self-hosted OpenAI-compatible endpoint.'
    }
  };

  /* ============================================================
     AUTH HEADER BUILDER & SECRET REDACTION
     ============================================================ */
  function buildAuthHeaders(profile, apiKey) {
    const headers = {};
    const key = String(apiKey || '').trim();
    const mode = profile.authMode || (profile.requiresKey ? 'bearer' : 'none');
    if (!key || mode === 'none') return headers;
    if (mode === 'bearer') headers['Authorization'] = `Bearer ${key}`;
    else if (mode === 'x-api-key') headers['x-api-key'] = key;
    else if (mode === 'x-goog-api-key') headers['x-goog-api-key'] = key;
    else if (mode === 'custom-header' && profile.customAuthHeader) {
      headers[String(profile.customAuthHeader).trim()] = key;
    }
    return headers;
  }

  function redactSecret(text, secret) {
    let out = String(text || '');
    const s = String(secret || '').trim();
    if (s && s.length >= 6) {
      out = out.split(s).join('[REDACTED_KEY]');
    }
    out = out.replace(/Bearer\s+[A-Za-z0-9._\-]{8,}/gi, 'Bearer [REDACTED_KEY]');
    out = out.replace(/(sk-[A-Za-z0-9_\-]{12,}|AIza[0-9A-Za-z_\-]{20,})/g, '[REDACTED_KEY]');
    return out;
  }

  /* ============================================================
     ADAPTERS (MODULAR PER-PROTOCOL IMPLEMENTATIONS)
     ============================================================ */
  const openaiCompatAdapter = {
    id: 'openai-compat',
    buildChatRequest(profile, { messages, model, temperature, maxTokens, stream, extraHeaders }, apiKey) {
      const base = normalizeBaseUrl(profile.baseUrl);
      const path = profile.chatPath || '/chat/completions';
      const url = base + (path.startsWith('/') ? path : '/' + path);
      const headers = {
        'Content-Type': 'application/json',
        ...buildAuthHeaders(profile, apiKey),
        ...(extraHeaders || {})
      };
      const body = {
        model: model || profile.model || profile.defaultModel || 'local-model',
        messages: messages.map(m => ({ role: m.role, content: String(m.content || '') })),
        temperature: typeof temperature === 'number' ? temperature : (profile.temperature ?? 0.2),
        max_tokens: typeof maxTokens === 'number' ? maxTokens : (profile.maxTokens || 4096),
        stream: Boolean(stream)
      };
      return { url, method: 'POST', headers, body: JSON.stringify(body), streamFormat: 'sse' };
    },
    parseChatResponse(json) {
      if (!json || typeof json !== 'object') return { ok: false, error: 'Response is not valid JSON.' };
      if (json.error) {
        const msg = typeof json.error === 'string' ? json.error : (json.error.message || JSON.stringify(json.error));
        return { ok: false, error: msg };
      }
      const choice = Array.isArray(json.choices) ? json.choices[0] : null;
      const content = choice && choice.message ? choice.message.content : (choice && choice.text);
      if (typeof content !== 'string') {
        return { ok: false, error: 'Missing choices[0].message.content in OpenAI-compatible response.' };
      }
      return {
        ok: true,
        text: content,
        finishReason: choice.finish_reason || '',
        usage: json.usage || null,
        model: json.model || ''
      };
    },
    parseStreamChunk(dataLine) {
      if (dataLine === '[DONE]') return { done: true };
      const json = JSON.parse(dataLine);
      const delta = json?.choices?.[0]?.delta;
      const text = typeof delta?.content === 'string' ? delta.content : '';
      return { done: false, text, finishReason: json?.choices?.[0]?.finish_reason || '' };
    },
    buildModelsRequest(profile, apiKey) {
      const base = normalizeBaseUrl(profile.baseUrl);
      const path = profile.modelsPath || '/models';
      const url = base + (path.startsWith('/') ? path : '/' + path);
      return { url, method: 'GET', headers: buildAuthHeaders(profile, apiKey) };
    },
    parseModelsResponse(json) {
      if (!json || typeof json !== 'object') return { ok: false, error: 'Models response is not JSON.', models: [] };
      const list = Array.isArray(json.data) ? json.data : (Array.isArray(json.models) ? json.models : null);
      if (!list) return { ok: false, error: 'Models payload missing "data" array.', models: [] };
      const models = list
        .map(m => (typeof m === 'string' ? m : (m.id || m.name || '')))
        .filter(Boolean);
      return { ok: true, models };
    }
  };

  const openrouterAdapter = {
    ...openaiCompatAdapter,
    id: 'openrouter',
    buildChatRequest(profile, opts, apiKey) {
      return openaiCompatAdapter.buildChatRequest(profile, {
        ...opts,
        extraHeaders: {
          'HTTP-Referer': 'https://github.com/amiraction0938/Corsair-Unbound',
          'X-Title': 'Corsair Unbound AI Script Studio',
          ...(opts.extraHeaders || {})
        }
      }, apiKey);
    }
  };

  const ollamaAdapter = {
    id: 'ollama',
    buildChatRequest(profile, { messages, model, temperature, maxTokens, stream }, apiKey) {
      const base = normalizeBaseUrl(profile.baseUrl);
      const path = profile.chatPath || '/api/chat';
      const url = base + (path.startsWith('/') ? path : '/' + path);
      const headers = { 'Content-Type': 'application/json', ...buildAuthHeaders(profile, apiKey) };
      const body = {
        model: model || profile.model || profile.defaultModel || 'qwen2.5-coder:7b',
        messages: messages.map(m => ({ role: m.role, content: String(m.content || '') })),
        stream: Boolean(stream),
        options: {
          temperature: typeof temperature === 'number' ? temperature : (profile.temperature ?? 0.2),
          num_predict: typeof maxTokens === 'number' ? maxTokens : (profile.maxTokens || 4096)
        }
      };
      if (profile.contextLength) body.options.num_ctx = Number(profile.contextLength);
      return { url, method: 'POST', headers, body: JSON.stringify(body), streamFormat: 'ndjson' };
    },
    parseChatResponse(json) {
      if (!json || typeof json !== 'object') return { ok: false, error: 'Invalid Ollama JSON response.' };
      if (json.error) return { ok: false, error: String(json.error) };
      const content = json.message ? json.message.content : json.response;
      if (typeof content !== 'string') {
        return { ok: false, error: 'Missing message.content in Ollama response.' };
      }
      return {
        ok: true,
        text: content,
        finishReason: json.done_reason || (json.done ? 'stop' : ''),
        model: json.model || ''
      };
    },
    parseStreamChunk(line) {
      const json = JSON.parse(line);
      if (json.error) throw new Error(String(json.error));
      const text = json.message && typeof json.message.content === 'string' ? json.message.content : '';
      return { done: Boolean(json.done), text };
    },
    buildModelsRequest(profile, apiKey) {
      const base = normalizeBaseUrl(profile.baseUrl);
      const path = profile.modelsPath || '/api/tags';
      const url = base + (path.startsWith('/') ? path : '/' + path);
      return { url, method: 'GET', headers: buildAuthHeaders(profile, apiKey) };
    },
    parseModelsResponse(json) {
      if (!json || !Array.isArray(json.models)) {
        return { ok: false, error: 'Ollama /api/tags response missing "models" array.', models: [] };
      }
      return { ok: true, models: json.models.map(m => m.name || m.model).filter(Boolean) };
    }
  };

  const geminiAdapter = {
    id: 'gemini',
    buildChatRequest(profile, { messages, model, temperature, maxTokens, stream }, apiKey) {
      const base = normalizeBaseUrl(profile.baseUrl);
      const mdl = encodeURIComponent(model || profile.model || profile.defaultModel || 'gemini-2.5-flash');
      const action = stream ? 'streamGenerateContent?alt=sse' : 'generateContent';
      const url = `${base}/models/${mdl}:${action}`;
      const headers = {
        'Content-Type': 'application/json',
        ...buildAuthHeaders({ ...profile, authMode: 'x-goog-api-key' }, apiKey)
      };
      const sysParts = messages.filter(m => m.role === 'system').map(m => ({ text: String(m.content || '') }));
      const contents = messages
        .filter(m => m.role !== 'system')
        .map(m => ({
          role: m.role === 'assistant' ? 'model' : 'user',
          parts: [{ text: String(m.content || '') }]
        }));
      const body = {
        contents,
        generationConfig: {
          temperature: typeof temperature === 'number' ? temperature : (profile.temperature ?? 0.2),
          maxOutputTokens: typeof maxTokens === 'number' ? maxTokens : (profile.maxTokens || 4096)
        }
      };
      if (sysParts.length) body.systemInstruction = { parts: sysParts };
      return { url, method: 'POST', headers, body: JSON.stringify(body), streamFormat: 'sse' };
    },
    parseChatResponse(json) {
      if (!json || typeof json !== 'object') return { ok: false, error: 'Invalid Gemini JSON response.' };
      if (json.error) return { ok: false, error: json.error.message || JSON.stringify(json.error) };
      const cand = Array.isArray(json.candidates) ? json.candidates[0] : null;
      const parts = cand?.content?.parts;
      if (!Array.isArray(parts)) {
        return { ok: false, error: 'Gemini response missing candidates[0].content.parts.' };
      }
      const text = parts.map(p => p.text || '').join('');
      return { ok: true, text, finishReason: cand.finishReason || '', usage: json.usageMetadata || null };
    },
    parseStreamChunk(dataLine) {
      const json = JSON.parse(dataLine);
      const parts = json?.candidates?.[0]?.content?.parts || [];
      const text = parts.map(p => p.text || '').join('');
      return { done: false, text, finishReason: json?.candidates?.[0]?.finishReason || '' };
    },
    buildModelsRequest(profile, apiKey) {
      const base = normalizeBaseUrl(profile.baseUrl);
      return {
        url: `${base}/models`,
        method: 'GET',
        headers: buildAuthHeaders({ ...profile, authMode: 'x-goog-api-key' }, apiKey)
      };
    },
    parseModelsResponse(json) {
      if (!json || !Array.isArray(json.models)) {
        return { ok: false, error: 'Gemini /models response missing "models" array.', models: [] };
      }
      const models = json.models
        .filter(m => !m.supportedGenerationMethods || m.supportedGenerationMethods.includes('generateContent'))
        .map(m => String(m.name || '').replace(/^models\//, ''))
        .filter(Boolean);
      return { ok: true, models };
    }
  };

  const anthropicAdapter = {
    id: 'anthropic',
    buildChatRequest(profile, { messages, model, temperature, maxTokens, stream }, apiKey) {
      const base = normalizeBaseUrl(profile.baseUrl);
      const path = profile.chatPath || '/messages';
      const url = base + (path.startsWith('/') ? path : '/' + path);
      const headers = {
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01',
        ...buildAuthHeaders({ ...profile, authMode: 'x-api-key' }, apiKey)
      };
      const system = messages.filter(m => m.role === 'system').map(m => m.content).join('\n\n');
      const conv = messages
        .filter(m => m.role !== 'system')
        .map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: String(m.content || '') }));
      const body = {
        model: model || profile.model || profile.defaultModel || 'claude-3-5-sonnet-latest',
        max_tokens: typeof maxTokens === 'number' ? maxTokens : (profile.maxTokens || 4096),
        temperature: typeof temperature === 'number' ? temperature : (profile.temperature ?? 0.2),
        messages: conv,
        stream: Boolean(stream)
      };
      if (system) body.system = system;
      return { url, method: 'POST', headers, body: JSON.stringify(body), streamFormat: 'sse' };
    },
    parseChatResponse(json) {
      if (!json || typeof json !== 'object') return { ok: false, error: 'Invalid Anthropic JSON response.' };
      if (json.error) return { ok: false, error: json.error.message || JSON.stringify(json.error) };
      if (!Array.isArray(json.content)) return { ok: false, error: 'Anthropic response missing content array.' };
      const text = json.content.filter(b => b.type === 'text').map(b => b.text || '').join('');
      return { ok: true, text, finishReason: json.stop_reason || '', usage: json.usage || null, model: json.model || '' };
    },
    parseStreamChunk(dataLine) {
      const json = JSON.parse(dataLine);
      if (json.type === 'message_stop') return { done: true };
      if (json.type === 'content_block_delta' && json.delta && json.delta.type === 'text_delta') {
        return { done: false, text: json.delta.text || '' };
      }
      return { done: false, text: '' };
    },
    buildModelsRequest(profile, apiKey) {
      const base = normalizeBaseUrl(profile.baseUrl);
      return {
        url: `${base}/models`,
        method: 'GET',
        headers: {
          'anthropic-version': '2023-06-01',
          ...buildAuthHeaders({ ...profile, authMode: 'x-api-key' }, apiKey)
        }
      };
    },
    parseModelsResponse(json) {
      if (!json || !Array.isArray(json.data)) {
        return { ok: false, error: 'Anthropic /models response missing "data" array.', models: [] };
      }
      return { ok: true, models: json.data.map(m => m.id).filter(Boolean) };
    }
  };

  const ADAPTERS = {
    'openai-compat': openaiCompatAdapter,
    openrouter: openrouterAdapter,
    ollama: ollamaAdapter,
    gemini: geminiAdapter,
    anthropic: anthropicAdapter
  };

  function getAdapter(profile) {
    const adapterId = (profile && profile.adapter) || (PRESETS[profile?.type]?.adapter) || 'openai-compat';
    return ADAPTERS[adapterId] || openaiCompatAdapter;
  }

  /* ============================================================
     PROFILE CRUD & CREDENTIAL STORAGE (SESSION-FIRST)
     ============================================================ */
  function createProfileFromPreset(presetType, overrides = {}) {
    const preset = PRESETS[presetType] || PRESETS['generic-local-openai'];
    const id = overrides.id || ('ai_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7));
    const baseUrl = normalizeBaseUrl(overrides.baseUrl !== undefined ? overrides.baseUrl : preset.baseUrl);
    const locality = classifyEndpointLocality(baseUrl);
    return {
      id,
      name: String(overrides.name || preset.name).trim(),
      type: preset.type,
      adapter: overrides.adapter || preset.adapter,
      category: locality === 'local' ? 'local' : (locality === 'lan' ? 'lan' : (preset.category === 'custom' ? 'custom' : 'cloud')),
      locality,
      baseUrl,
      chatPath: overrides.chatPath !== undefined ? overrides.chatPath : preset.chatPath,
      modelsPath: overrides.modelsPath !== undefined ? overrides.modelsPath : preset.modelsPath,
      authMode: overrides.authMode !== undefined ? overrides.authMode : preset.authMode,
      customAuthHeader: overrides.customAuthHeader || '',
      requiresKey: overrides.requiresKey !== undefined ? Boolean(overrides.requiresKey) : preset.requiresKey,
      model: String(overrides.model !== undefined ? overrides.model : preset.defaultModel).trim(),
      discoveredModels: Array.isArray(overrides.discoveredModels) ? overrides.discoveredModels : [],
      supportsDiscovery: overrides.supportsDiscovery !== undefined ? Boolean(overrides.supportsDiscovery) : preset.supportsDiscovery,
      supportsStreaming: overrides.supportsStreaming !== undefined ? Boolean(overrides.supportsStreaming) : preset.supportsStreaming,
      temperature: typeof overrides.temperature === 'number' ? overrides.temperature : 0.2,
      maxTokens: Number(overrides.maxTokens) || 4096,
      contextLength: Number(overrides.contextLength) || 0,
      timeoutMs: Number(overrides.timeoutMs) || 60000,
      keyPersistence: overrides.keyPersistence === 'persistent' ? 'persistent' : 'session',
      createdAt: overrides.createdAt || Date.now(),
      updatedAt: Date.now()
    };
  }

  function defaultSeedProfiles() {
    return [
      createProfileFromPreset('llamacpp', {
        id: 'ai_default_llamacpp',
        name: 'Local llama.cpp (9101)',
        baseUrl: 'http://127.0.0.1:9101/v1',
        model: 'local-model'
      }),
      createProfileFromPreset('ollama', {
        id: 'ai_default_ollama',
        name: 'Local Ollama (11434)',
        baseUrl: 'http://127.0.0.1:11434',
        model: 'qwen2.5-coder:7b'
      })
    ];
  }

  async function listProfiles() {
    const res = await chrome.storage.local.get([PROFILES_KEY, DEFAULT_PROFILE_KEY]);
    let profiles = Array.isArray(res[PROFILES_KEY]) ? res[PROFILES_KEY] : null;
    if (!profiles || profiles.length === 0) {
      profiles = defaultSeedProfiles();
      await chrome.storage.local.set({ [PROFILES_KEY]: profiles, [DEFAULT_PROFILE_KEY]: profiles[0].id });
    }
    const defaultId = res[DEFAULT_PROFILE_KEY] || profiles[0].id;
    const keyMeta = await getKeyStatuses(profiles.map(p => p.id));
    return {
      profiles: profiles.map(p => ({
        ...p,
        locality: classifyEndpointLocality(p.baseUrl),
        hasKey: Boolean(keyMeta[p.id]?.hasKey),
        keyStorage: keyMeta[p.id]?.storage || 'none',
        isDefault: p.id === defaultId
      })),
      defaultProfileId: defaultId
    };
  }

  async function getProfile(id) {
    const { profiles } = await listProfiles();
    return profiles.find(p => p.id === id) || null;
  }

  async function getDefaultProfile() {
    const { profiles, defaultProfileId } = await listProfiles();
    return profiles.find(p => p.id === defaultProfileId) || profiles[0] || null;
  }

  async function saveProfile(input, apiKey) {
    const urlCheck = validateBaseUrl(input.baseUrl);
    if (!urlCheck.ok) return { ok: false, error: urlCheck.error };

    const { profiles, defaultProfileId } = await listProfiles();
    const existingIdx = input.id ? profiles.findIndex(p => p.id === input.id) : -1;
    const base = existingIdx >= 0 ? profiles[existingIdx] : {};
    const next = createProfileFromPreset(input.type || base.type || 'generic-local-openai', {
      ...base,
      ...input,
      id: existingIdx >= 0 ? base.id : (input.id || undefined),
      baseUrl: urlCheck.url,
      createdAt: base.createdAt || Date.now()
    });
    // Never store raw apiKey inside profile object
    delete next.apiKey;
    delete next.hasKey;
    delete next.keyStorage;
    delete next.isDefault;

    const cleanList = profiles.map(({ hasKey, keyStorage, isDefault, ...rest }) => rest);
    if (existingIdx >= 0) cleanList[existingIdx] = next;
    else cleanList.push(next);

    const updates = { [PROFILES_KEY]: cleanList };
    if (!defaultProfileId || input.setDefault) updates[DEFAULT_PROFILE_KEY] = next.id;
    await chrome.storage.local.set(updates);

    if (typeof apiKey === 'string') {
      if (apiKey.trim()) {
        await setApiKey(next.id, apiKey.trim(), next.keyPersistence);
      } else if (input.clearApiKey) {
        await clearApiKey(next.id);
      }
    }
    return { ok: true, profile: next };
  }

  async function duplicateProfile(id) {
    const orig = await getProfile(id);
    if (!orig) return { ok: false, error: 'Profile not found.' };
    return saveProfile({
      ...orig,
      id: undefined,
      name: `${orig.name} (Copy)`,
      setDefault: false
    });
  }

  async function deleteProfile(id) {
    const { profiles, defaultProfileId } = await listProfiles();
    const next = profiles.filter(p => p.id !== id).map(({ hasKey, keyStorage, isDefault, ...rest }) => rest);
    await clearApiKey(id);
    const updates = { [PROFILES_KEY]: next };
    if (defaultProfileId === id) {
      updates[DEFAULT_PROFILE_KEY] = next[0] ? next[0].id : '';
    }
    await chrome.storage.local.set(updates);
    return { ok: true, defaultProfileId: updates[DEFAULT_PROFILE_KEY] ?? defaultProfileId };
  }

  async function setDefaultProfile(id) {
    const p = await getProfile(id);
    if (!p) return { ok: false, error: 'Profile not found.' };
    await chrome.storage.local.set({ [DEFAULT_PROFILE_KEY]: id });
    return { ok: true, defaultProfileId: id };
  }

  /* ============================================================
     CREDENTIAL STORAGE (SESSION DEFAULT, OPT-IN PERSISTENT)
     ============================================================ */
  function _b64(str) {
    try { return btoa(unescape(encodeURIComponent(str))); } catch { return ''; }
  }
  function _unb64(str) {
    try { return decodeURIComponent(escape(atob(str))); } catch { return ''; }
  }

  async function setApiKey(profileId, key, mode = 'session') {
    const clean = String(key || '').trim();
    if (!clean) return clearApiKey(profileId);
    // Always clear the opposite store so secrets do not duplicate
    if (mode === 'persistent') {
      if (chrome.storage.session) {
        const s = (await chrome.storage.session.get(SESSION_KEYS_KEY))[SESSION_KEYS_KEY] || {};
        delete s[profileId];
        await chrome.storage.session.set({ [SESSION_KEYS_KEY]: s });
      }
      const p = (await chrome.storage.local.get(PERSIST_KEYS_KEY))[PERSIST_KEYS_KEY] || {};
      p[profileId] = { v: 1, d: _b64(clean) };
      await chrome.storage.local.set({ [PERSIST_KEYS_KEY]: p });
      return { ok: true, storage: 'persistent' };
    }
    const p = (await chrome.storage.local.get(PERSIST_KEYS_KEY))[PERSIST_KEYS_KEY] || {};
    if (p[profileId]) {
      delete p[profileId];
      await chrome.storage.local.set({ [PERSIST_KEYS_KEY]: p });
    }
    if (chrome.storage.session) {
      const s = (await chrome.storage.session.get(SESSION_KEYS_KEY))[SESSION_KEYS_KEY] || {};
      s[profileId] = clean;
      await chrome.storage.session.set({ [SESSION_KEYS_KEY]: s });
      return { ok: true, storage: 'session' };
    }
    return { ok: false, error: 'chrome.storage.session unavailable.' };
  }

  async function getApiKey(profileId) {
    if (chrome.storage.session) {
      const s = (await chrome.storage.session.get(SESSION_KEYS_KEY))[SESSION_KEYS_KEY] || {};
      if (typeof s[profileId] === 'string' && s[profileId]) return s[profileId];
    }
    const p = (await chrome.storage.local.get(PERSIST_KEYS_KEY))[PERSIST_KEYS_KEY] || {};
    if (p[profileId] && p[profileId].d) return _unb64(p[profileId].d);
    return '';
  }

  async function clearApiKey(profileId) {
    if (chrome.storage.session) {
      const s = (await chrome.storage.session.get(SESSION_KEYS_KEY))[SESSION_KEYS_KEY] || {};
      if (profileId in s) {
        delete s[profileId];
        await chrome.storage.session.set({ [SESSION_KEYS_KEY]: s });
      }
    }
    const p = (await chrome.storage.local.get(PERSIST_KEYS_KEY))[PERSIST_KEYS_KEY] || {};
    if (profileId in p) {
      delete p[profileId];
      await chrome.storage.local.set({ [PERSIST_KEYS_KEY]: p });
    }
    return { ok: true };
  }

  async function getKeyStatuses(profileIds) {
    const s = chrome.storage.session
      ? ((await chrome.storage.session.get(SESSION_KEYS_KEY))[SESSION_KEYS_KEY] || {})
      : {};
    const p = (await chrome.storage.local.get(PERSIST_KEYS_KEY))[PERSIST_KEYS_KEY] || {};
    const out = {};
    for (const id of profileIds) {
      if (s[id]) out[id] = { hasKey: true, storage: 'session' };
      else if (p[id] && p[id].d) out[id] = { hasKey: true, storage: 'persistent' };
      else out[id] = { hasKey: false, storage: 'none' };
    }
    return out;
  }

  return {
    PRESETS,
    ADAPTERS,
    classifyEndpointLocality,
    normalizeBaseUrl,
    validateBaseUrl,
    buildAuthHeaders,
    redactSecret,
    getAdapter,
    createProfileFromPreset,
    listProfiles,
    getProfile,
    getDefaultProfile,
    saveProfile,
    duplicateProfile,
    deleteProfile,
    setDefaultProfile,
    setApiKey,
    getApiKey,
    clearApiKey,
    getKeyStatuses
  };
})();

globalThis.CorsairAIProviders = CorsairAIProviders;
