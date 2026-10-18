import { describe, it, expect } from 'vitest';
import '../core/updater.js';

describe('CorsairUpdater — Path A', () => {
  it('parseVersion parses simple semver', () => {
    expect(CorsairUpdater.parseVersion('1.8.1')).toEqual({ major: 1, minor: 8, patch: 1, str: '1.8.1' });
    expect(CorsairUpdater.parseVersion('v1.8.1')).toEqual({ major: 1, minor: 8, patch: 1, str: '1.8.1' });
  });

  it('parseVersion rejects pre-releases (strict semver)', () => {
    // در Path A ما فقط نسخه‌های پایدار (Stable) رو قبول می‌کنیم
    expect(CorsairUpdater.parseVersion('1.8.1-beta.2')).toBeNull();
    expect(CorsairUpdater.parseVersion('1.8.1-alpha')).toBeNull();
  });

  it('returns null for invalid formats', () => {
    expect(CorsairUpdater.parseVersion('not-a-version')).toBeNull();
    expect(CorsairUpdater.parseVersion('1.8')).toBeNull();
  });

  it('compareVersions works correctly', () => {
    expect(CorsairUpdater.compareVersions('1.8.0', '1.8.1')).toBe(-1);
    expect(CorsairUpdater.compareVersions('1.9.0', '1.8.1')).toBe(1);
    expect(CorsairUpdater.compareVersions('1.8.0', '1.8.0')).toBe(0);
    expect(CorsairUpdater.compareVersions('2.0.0', '1.9.9')).toBe(1);
  });

  it('getCurrentVersion returns a string from manifest', () => {
    const v = CorsairUpdater.getCurrentVersion();
    expect(typeof v).toBe('string');
    expect(v).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('has the necessary constants exposed', () => {
    expect(CorsairUpdater.latestJsonUrl).toContain('latest.json');
    expect(CorsairUpdater.launcherDownloadUrl).toContain('corsair-unbound-updater.ps1');
  });
});