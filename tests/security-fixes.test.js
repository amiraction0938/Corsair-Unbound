import { describe, it, expect, beforeAll } from 'vitest';
import { loadCore } from './helpers/load-core.js';

beforeAll(() => {
  globalThis.chrome = globalThis.chrome || { runtime: { getManifest: () => ({ version: '1.10.0' }), id: 'x', getURL: (p) => 'chrome-extension://x/' + p }, storage: { local: { get: async () => ({}), set: async () => {} } } };
  loadCore('core/updater.js');
  loadCore('core/userscripts.js');
});

describe('Updater: download url must be exactly this repo release asset', () => {
  const ok = 'https://github.com/amiraction0938/Corsair-Unbound/releases/download/v1.2.3/corsair-unbound-extension.zip';
  it('accepts the genuine release url', () => {
    expect(CorsairUpdater.isTrustedDownloadUrl(ok, 'v1.2.3')).toBe(true);
  });
  it('rejects path traversal that passed the old startsWith() check', () => {
    expect(CorsairUpdater.isTrustedDownloadUrl('https://github.com/amiraction0938/Corsair-Unbound/../../evil/repo/releases/download/v1.2.3/corsair-unbound-extension.zip', 'v1.2.3')).toBe(false);
  });
  it('rejects any other repository on objects.githubusercontent.com', () => {
    expect(CorsairUpdater.isTrustedDownloadUrl('https://objects.githubusercontent.com/github-production-release-asset/1/corsair-unbound-extension.zip', 'v1.2.3')).toBe(false);
  });
  it('rejects wrong tag, wrong file, http, credentials, port, query', () => {
    expect(CorsairUpdater.isTrustedDownloadUrl(ok, 'v9.9.9')).toBe(false);
    expect(CorsairUpdater.isTrustedDownloadUrl(ok.replace('extension.zip', 'other.zip'), 'v1.2.3')).toBe(false);
    expect(CorsairUpdater.isTrustedDownloadUrl(ok.replace('https:', 'http:'), 'v1.2.3')).toBe(false);
    expect(CorsairUpdater.isTrustedDownloadUrl(ok.replace('github.com', 'user:pw@github.com'), 'v1.2.3')).toBe(false);
    expect(CorsairUpdater.isTrustedDownloadUrl(ok.replace('github.com', 'github.com:8443'), 'v1.2.3')).toBe(false);
    expect(CorsairUpdater.isTrustedDownloadUrl(ok + '?x=1', 'v1.2.3')).toBe(false);
    expect(CorsairUpdater.isTrustedDownloadUrl('https://github.com.evil.com/amiraction0938/Corsair-Unbound/releases/download/v1.2.3/corsair-unbound-extension.zip', 'v1.2.3')).toBe(false);
  });
});

describe('Userscripts: GM_xmlhttpRequest access policy', () => {
  const D = (url, connect, page = 'https://example.com/page') => CorsairUserScripts.connectDecision(url, connect, page);

  it('blocks loopback / LAN / link-local targets unless named in @connect', () => {
    for (const u of ['http://localhost:8080/', 'http://127.0.0.1/', 'http://192.168.1.1/', 'http://10.0.0.5/', 'http://172.20.1.1/', 'http://169.254.169.254/latest/meta-data/', 'http://[::1]/', 'http://printer.local/', 'http://2130706433/']) {
      expect(D(u, ['*']).deny, u).toBe('blocked-private-address');
      expect(D(u, []).deny, u).toBe('blocked-private-address');
    }
  });
  it('allows a private host only when @connect names it explicitly', () => {
    expect(D('http://192.168.1.1/', ['192.168.1.1']).allow).toBe(true);
    expect(D('http://localhost:3000/', ['localhost']).allow).toBe(true);
  });
  it('sends cookies only to hosts listed in @connect or the page\'s own site', () => {
    expect(D('https://api.example.com/x', []).anonymous).toBe(false);          // same site
    expect(D('https://api.other.org/x', ['other.org']).anonymous).toBe(false); // listed
    expect(D('https://bank.com/account', []).anonymous).toBe(true);            // not listed: NO cookies
    expect(D('https://bank.com/account', ['*']).anonymous).toBe(false);        // user opted in with *
  });
  it('does not treat a lookalike host as a listed host', () => {
    expect(D('https://evilother.org/', ['other.org']).anonymous).toBe(true);
  });
  it('isPrivateHost covers the common ranges and leaves public hosts alone', () => {
    expect(CorsairUserScripts.isPrivateHost('172.16.0.1')).toBe(true);
    expect(CorsairUserScripts.isPrivateHost('172.32.0.1')).toBe(false);
    expect(CorsairUserScripts.isPrivateHost('8.8.8.8')).toBe(false);
    expect(CorsairUserScripts.isPrivateHost('example.com')).toBe(false);
    expect(CorsairUserScripts.isPrivateHost('fd12:3456::1')).toBe(true);
  });
});
