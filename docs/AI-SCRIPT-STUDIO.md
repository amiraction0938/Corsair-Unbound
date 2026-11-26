# Corsair Unbound — AI Script Studio & Multi-Provider Guide (v1.13.0)

## 1. Automatic Userscript Execution & Chrome Permissions

Corsair Unbound registers enabled userscripts via Chrome's Manifest V3 `chrome.userScripts` API so matching scripts execute automatically at their declared `@run-at` timing (`document-start`, `document-body`, `document-end`, `document-idle`) without clicking the extension toolbar icon.

- **Chrome 138+:** Open `chrome://extensions/?id=<extension-id>` and turn **ON** **Allow User Scripts**.
- **Chrome 120–137:** Open `chrome://extensions/` and turn **ON** **Developer mode**.
- **Extension Updates & Service Worker Restarts:** Chrome clears dynamic `chrome.userScripts` registrations on extension updates. Corsair Unbound automatically reconciles registrations on `onInstalled`, `onStartup`, and top-frame navigations (`ensureSynced`) without unregistering unrelated scripts.
- **Already-Open Tabs:** Enabling or creating a script does not silently reload existing tabs. Use **▶ Run** in the toolbar popup or **Test on This Tab** in AI Script Studio for an explicit, one-time tab run. Future matching navigations always run automatically.

## 2. AI Script Studio Workflow

1. Navigate to the target website and open the **Corsair Unbound** toolbar popup.
2. Select a configured local or cloud AI provider in the **AI Script Studio** card, enter your request, and click **Generate** (or **Full Studio**).
3. AI Script Studio binds to the **originating tab ID** so switching tabs never targets the wrong site.
4. Sanitized website context strips URL query strings and fragments by default and never collects password values, credit card fields, hidden inputs, cookies, or tokens. Webpage text is wrapped in `<UNTRUSTED_PAGE_CONTEXT>` to resist prompt injection.
5. Generated scripts undergo CSP-safe lexical syntax validation, metadata checks, and static security analysis (flagging `eval`, remote script injection, obfuscation, data exfiltration, `@match *://*/*`, `@connect *`, aggressive polling, etc.).
6. Click **Test on This Tab** for a **one-time, non-registered preview** (Chrome 135+ `chrome.userScripts.execute()`, defaulting to isolated `USER_SCRIPT` world). On Chrome 120–134, live preview reports unsupported honestly and guides you to save and reload after static validation.
7. Approve explicitly via **Save as Draft**, **Save & Enable** (registers through `CorsairUserScripts.save()`), or **Discard**.

## 3. Supported AI Providers (Local-First)

### Local Inference Servers (Recommended Default)
| Provider | Default Endpoint | Mode |
| --- | --- | --- |
| **llama.cpp Server** | `http://127.0.0.1:9101/v1` (port configurable) | OpenAI-compatible |
| **Ollama** | `http://127.0.0.1:11434` | Native (`/api/chat`, `/api/tags`) or OpenAI-compatible |
| **LM Studio** | `http://127.0.0.1:1234/v1` | OpenAI-compatible |
| **vLLM** | `http://127.0.0.1:8000/v1` | OpenAI-compatible |
| **LocalAI** | `http://127.0.0.1:8080/v1` | OpenAI-compatible |
| **Jan** | `http://127.0.0.1:1337/v1` | OpenAI-compatible |
| **Text Generation WebUI** | `http://127.0.0.1:5000/v1` (`--api` enabled) | OpenAI-compatible |
| **KoboldCpp** | `http://127.0.0.1:5001/v1` | OpenAI-compatible |
| **Generic Local OpenAI-Compatible** | Configurable | OpenAI-compatible |

### Cloud Providers
OpenAI, Google Gemini (native `x-goog-api-key`), Anthropic Claude (native `/messages` + `x-api-key`), OpenRouter, DeepSeek, Alibaba Qwen / DashScope, Mistral AI, Groq, xAI (Grok), and Custom OpenAI-Compatible HTTPS endpoints.

## 4. Credential Security & Privacy Guarantees
- All AI network requests run exclusively in the extension's trusted background service worker — never from webpage JavaScript.
- API keys default to **`chrome.storage.session`** (cleared when the browser closes). Optional persistent storage in `chrome.storage.local` uses app-level encoding and is explicitly disclosed as **not** hardware-vault encryption.
- Corsair Unbound **never** silently falls back from a failed local provider to a cloud provider.
