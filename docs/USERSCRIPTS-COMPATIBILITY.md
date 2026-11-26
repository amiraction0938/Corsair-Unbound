# Corsair Unbound — Tampermonkey Compatibility Matrix

Corsair Unbound's Userscripts engine is built on Chrome's official Manifest V3 `chrome.userScripts` API (Chrome 120+). This document details directive support, `GM_*` / `GM.*` API semantics, security boundaries, and genuine Chrome MV3 platform limitations.

## 1. Metadata Directives

| Directive | Status | Notes |
| --- | --- | --- |
| `@name`, `@namespace`, `@version`, `@description`, `@author` | Supported | Full UTF-8 BOM, CRLF/LF/CR, and whitespace tolerance |
| `@name:<lang>`, `@description:<lang>` | Supported | Stored in `meta.localized` (e.g. `@name:fa`, `@description:en`) |
| `@homepage`, `@homepageURL`, `@website`, `@source` | Supported | Preserved in script metadata |
| `@icon`, `@iconURL`, `@defaulticon`, `@icon64`, `@icon64URL` | Supported | Preserved in script metadata |
| `@updateURL`, `@downloadURL`, `@installURL`, `@supportURL`, `@license`, `@copyright` | Supported | Used for safe remote updates (never overwrites local edits without confirmation) |
| `@match`, `@exclude-match` | Supported | Converted to Chrome match patterns (including IDN/punycode, ports, `file:///*`, `<all_urls>`); patterns Chrome cannot express (e.g. `.tld`, wildcard host middle) automatically use runtime URL filtering |
| `@include`, `@exclude` | Supported | Glob wildcards (`*`, `?`), `.tld` magic TLD, and `/regex/flags` literals |
| `@grant` | Supported | Enforced both in the injected scope and on the extension bridge |
| `@require` | Supported | Fetched over `https:`, `data:`, or loopback `http://localhost`, cached, HTML soft-404 checked, and syntax-validated before registration |
| `@resource` | Supported | Fetched and cached as text + `data:` URL |
| `@connect` | Supported | Enforced on `GM_xmlhttpRequest` / `GM.xmlHttpRequest`; supports hostnames, `*.domain.com`, `self`, and `*`; private/loopback IPs blocked unless explicitly listed |
| `@run-at` | Supported | `document-start`, `document-body` (MutationObserver wait), `document-end`, `document-idle`, `context-menu` |
| `@noframes` | Supported | Maps to `allFrames: false` |
| `@inject-into` | Supported | `auto` (default), `page` (`MAIN` world), `content` (`USER_SCRIPT` world) |
| `@top-level-await` | Supported | Top-level `await` and early `return` work in all scripts |
| `@tag`, `@antifeature` | Supported | Parsed and preserved |
| `@sandbox` | Partial | `raw` maps to `MAIN`; `javascript`/`dom` map to `USER_SCRIPT` |
| `@unwrap`, `@webRequest`, `@run-in` | Unsupported (detected & preserved) | Reported in `meta.unsupported` with explanation; never silently discarded |

## 2. GM API Compatibility

| API | Sync (`GM_*`) | Async (`GM.*`) | Status | Notes |
| --- | --- | --- | --- | --- |
| `GM_getValue` / `GM.getValue` | Yes | Yes (Promise) | Supported | Values preloaded into sync cache before script runs |
| `GM_setValue` / `GM.setValue` | Yes | Yes (Promise) | Supported | Isolated per-script storage (`cus:vals:<id>`) |
| `GM_deleteValue` / `GM.deleteValue` | Yes | Yes (Promise) | Supported | Fires local and cross-tab listeners |
| `GM_listValues` / `GM.listValues` | Yes | Yes (Promise) | Supported | Returns array of stored keys |
| `GM_getValues` / `GM.getValues` | Yes | Yes (Promise) | Supported | Supports array of keys, default-value map, or all values |
| `GM_setValues` / `GM.setValues` | Yes | Yes (Promise) | Supported | Atomic batch storage write |
| `GM_deleteValues` / `GM.deleteValues` | Yes | Yes (Promise) | Supported | Atomic batch storage delete |
| `GM_addValueChangeListener` / `GM_removeValueChangeListener` | Yes | Yes | Supported | Fires with `remote=false` locally and `remote=true` across tabs/frames via `chrome.runtime.onUserScriptConnect` |
| `GM_xmlhttpRequest` / `GM.xmlHttpRequest` | Callback + `{ abort }` | Promise + `.abort()` | Supported | Cross-origin via service worker; supports `method`, `headers`, `data` (string/binary/FormData/Blob/ArrayBuffer), `responseType` (`text`/`json`/`blob`/`arraybuffer`/`document`), `timeout`, `redirect`, `anonymous`, `overrideMimeType`, full lifecycle callbacks (`onloadstart`, `onreadystatechange`, `onprogress`, `onload`, `onerror`, `ontimeout`, `onabort`, `onloadend`), auto-abort on `pagehide` |
| `GM_getResourceText` / `GM.getResourceText` | Yes | Yes (Promise) | Supported | Returns cached UTF-8 text |
| `GM_getResourceURL` / `GM.getResourceUrl` | Yes | Yes (Promise) | Supported | Returns cached `data:` URL |
| `GM_openInTab` / `GM.openInTab` | Yes | Yes (Promise) | Supported | Restricts to `http:`, `https:`, `about:blank`; returns `{ closed, close(), onclose }` |
| `GM_download` / `GM.download` | Yes | Yes (Promise) | Supported | Uses `chrome.downloads`; blocks executable/script file extensions |
| `GM_notification` / `GM.notification` | Yes | Yes (Promise) | Supported | Uses `chrome.notifications` |
| `GM_setClipboard` / `GM.setClipboard` | Yes | Yes (Promise) | Supported | Supports `text/plain` and `text/html` (`ClipboardItem` + fallback) |
| `GM_addStyle` / `GM.addStyle` | Yes | Yes (Promise) | Supported | Injects `<style>` into `head` or `documentElement` |
| `GM_addElement` / `GM.addElement` | Yes | Yes (Promise) | Supported | Creates & appends DOM element |
| `GM_registerMenuCommand` / `GM_unregisterMenuCommand` | Yes | Yes (Promise) | Supported | Rendered in Corsair toolbar popup with per-instance random token authentication |
| `GM_log` / `GM.log` | Yes | Yes (Promise) | Supported | Logs to console |
| `GM_info` / `GM.info` | Object | Object | Supported | Full metadata + handler/version/uuid/injectInto |
| `window.onurlchange` | Event | — | Supported | Hooks `history.pushState`, `replaceState`, `popstate`, `hashchange` for SPAs |
| `unsafeWindow` | Partial | — | Partial | Direct page `window` in `MAIN` world (`@inject-into page`); isolated `window` in `USER_SCRIPT` world (Chrome MV3 does not expose direct cross-world JS object wrappers like Firefox's `wrappedJSObject`) |
| `GM_getTab` / `GM_saveTab` / `GM_getTabs` | Yes | Yes (Promise) | Supported | Per-tab session state stored in `chrome.storage.session`, auto-cleaned on tab close |
| `GM_cookie`, `GM_webRequest`, `window.close`, `window.focus` | — | — | Unsupported | Restricted by Chrome MV3 / extension security architecture |

## 3. Security Model

- **Bridge capability checks**: Every `onUserScriptMessage` call verifies that the script exists, is enabled, and declared a matching `@grant` directive.
- **Resource ownership**: XHR abort handles and `GM_openInTab` tab handles are bound to the originating `scriptId` so one script cannot cancel another script's requests or close another script's tabs.
- **`@connect` enforcement**: Public hosts not listed in `@connect` (and not `self` / `*`) are stripped of cookies (`credentials: 'omit'`). Private, loopback, and link-local addresses are denied unless explicitly named in `@connect` or matching the page's own host, and redirect targets are re-checked.
- **Menu command authentication**: Sandbox-world scripts register menu commands over the private `onUserScriptMessage` bridge with a 128-bit random token; page scripts cannot forge or trigger them.
