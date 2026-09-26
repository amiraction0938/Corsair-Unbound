import { describe, it, expect, beforeAll } from 'vitest';
import { loadCore } from './helpers/load-core.js';

beforeAll(() => {
  loadCore('core/updater.js');
});

describe('CorsairUpdater.parseVersion', () => {
  it('parses standard semver', () => {
    const v = CorsairUpdater.parseVersion('1.8.1');
    expect(v).toEqual({ major: 1, minor: 8, patch: 1, str: '1.8.1' });
  });

  it('parses version with leading v', () => {
    const v = CorsairUpdater.parseVersion('v1.8.1');
    expect(v).toEqual({ major: 1, minor: 8, patch: 1, str: '1.8.1' });
  });

  it('parses version with extra suffix', () => {
    const v = CorsairUpdater.parseVersion('1.8.1-beta.2');
    expect(v).toEqual({ major: 1, minor: 8, patch: 1, str: '1.8.1' });
  });

  it('returns null for invalid input', () => {
    expect(CorsairUpdater.parseVersion('')).toBeNull();
    expect(CorsairUpdater.parseVersion('abc')).toBeNull();
    expect(CorsairUpdater.parseVersion('1.8')).toBeNull();
    expect(CorsairUpdater.parseVersion(null)).toBeNull();
    expect(CorsairUpdater.parseVersion(undefined)).toBeNull();
  });
});

describe('CorsairUpdater.compareVersions', () => {
  it('returns 0 for equal versions', () => {
    expect(CorsairUpdater.compareVersions('1.8.1', '1.8.1')).toBe(0);
    expect(CorsairUpdater.compareVersions('v1.8.1', '1.8.1')).toBe(0);
  });

  it('returns positive when first is newer', () => {
    expect(CorsairUpdater.compareVersions('1.8.1', '1.8.0')).toBe(1);
    expect(CorsairUpdater.compareVersions('1.9.0', '1.8.9')).toBe(1);
    expect(CorsairUpdater.compareVersions('2.0.0', '1.99.99')).toBe(1);
  });

  it('returns negative when second is newer', () => {
    expect(CorsairUpdater.compareVersions('1.8.0', '1.8.1')).toBe(-1);
    expect(CorsairUpdater.compareVersions('1.8.1', '1.9.0')).toBe(-1);
    expect(CorsairUpdater.compareVersions('1.99.99', '2.0.0')).toBe(-1);
  });

  it('returns 0 when either is invalid', () => {
    expect(CorsairUpdater.compareVersions('abc', '1.8.1')).toBe(0);
    expect(CorsairUpdater.compareVersions('1.8.1', 'xyz')).toBe(0);
  });
});

describe('CorsairUpdater._normalizeTag', () => {
  it('strips leading v', () => {
    expect(CorsairUpdater._normalizeTag('v1.8.1')).toBe('1.8.1');
    expect(CorsairUpdater._normalizeTag('V1.8.1')).toBe('1.8.1');
  });

  it('leaves plain versions alone', () => {
    expect(CorsairUpdater._normalizeTag('1.8.1')).toBe('1.8.1');
  });

  it('returns empty for invalid input', () => {
    expect(CorsairUpdater._normalizeTag('')).toBe('');
    expect(CorsairUpdater._normalizeTag(null)).toBe('');
  });
});

describe('CorsairUpdater._pickReleaseAsset', () => {
  const REAL_URL = 'https://github.com/amiraction0938/Corsair-Unbound/releases/download/v1.8.2/corsair-unbound-extension.zip';

  it('picks the canonical zip asset from a real-looking release', () => {
    const assets = [
      { name: 'something-else.txt', state: 'uploaded', browser_download_url: 'https://github.com/amiraction0938/Corsair-Unbound/releases/download/v1.8.2/something-else.txt' },
      { name: 'corsair-unbound-extension.zip', state: 'uploaded', browser_download_url: REAL_URL }
    ];
    const picked = CorsairUpdater._pickReleaseAsset(assets);
    expect(picked).not.toBeNull();
    expect(picked.browser_download_url).toBe(REAL_URL);
  });

  it('returns null if no matching asset', () => {
    expect(CorsairUpdater._pickReleaseAsset([])).toBeNull();
    expect(CorsairUpdater._pickReleaseAsset([
      { name: 'other.zip', state: 'uploaded', browser_download_url: REAL_URL }
    ])).toBeNull();
  });

  it('ignores non-uploaded assets', () => {
    expect(CorsairUpdater._pickReleaseAsset([
      { name: 'corsair-unbound-extension.zip', state: 'processing', browser_download_url: REAL_URL }
    ])).toBeNull();
  });

  it('rejects non-GitHub URLs (security guard)', () => {
    // Even if the asset name matches, a non-GitHub URL must be
    // rejected — this is the security guard against repo hijack
    // or MITM redirection of the download.
    expect(CorsairUpdater._pickReleaseAsset([
      { name: 'corsair-unbound-extension.zip', state: 'uploaded', browser_download_url: 'https://evil.example/z.zip' }
    ])).toBeNull();
    expect(CorsairUpdater._pickReleaseAsset([
      { name: 'corsair-unbound-extension.zip', state: 'uploaded', browser_download_url: 'http://github.com/amiraction0938/Corsair-Unbound/releases/download/v1.8.2/x.zip' }
    ])).toBeNull();
  });

  it('handles invalid input', () => {
    expect(CorsairUpdater._pickReleaseAsset(null)).toBeNull();
    expect(CorsairUpdater._pickReleaseAsset('not-array')).toBeNull();
  });
});