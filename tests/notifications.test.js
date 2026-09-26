/* ============================================================
   NOTIFICATION CENTER — STATIC SAFEGUARDS
   ------------------------------------------------------------
   The Notification Center implementation lives inside the
   `dashboard.js` IIFE, coupled to DOM rendering and app state.
   It cannot be unit-tested without extracting that logic into a
   standalone module (a Phase-8 refactor).

   What we CAN do in Phase 7 is guard the specific behaviors that
   have caused bugs in the past or would break silently:

     1. The storage key must remain `notifCenterLastSeen`.
     2. markNotificationsRead must use `Date.now() + 1` to avoid a
        same-millisecond race with freshly-written events.
     3. The notification list must use escapeHtml() on all
        user-controllable fields (domain / type / destination).
   ============================================================ */
import { describe, it, expect } from 'vitest';
import { readSource } from './helpers/load-core.js';

describe('Notification Center — source-level invariants', () => {
  const src = readSource('dashboard.js');

  it('uses the canonical storage key "notifCenterLastSeen"', () => {
    expect(src).toMatch(/['"]notifCenterLastSeen['"]/);
  });

  it('markNotificationsRead uses Date.now() + 1 (same-millisecond race guard)', () => {
    // Regression guard: a previous version used `Date.now()`, which
    // could leave a notification marked as unread if it was written
    // in the same millisecond as the mark-all-read click.
    const fn = src.match(/function\s+markNotificationsRead\s*\(\)\s*\{[\s\S]*?\n\s{2}\}/);
    expect(fn, 'markNotificationsRead() must exist').toBeTruthy();
    expect(fn[0]).toMatch(/Date\.now\(\)\s*\+\s*1/);
  });

  it('renders notification fields through escapeHtml()', () => {
    const start = src.indexOf('function renderNotifications');
    expect(start, 'renderNotifications() must exist').toBeGreaterThan(-1);
    // Grab a generous slice of the function body — nested braces make
    // a regex approach fragile, so we slice by character window.
    const body = src.slice(start, start + 2500);
    expect(body, 'title must be escaped').toMatch(/escapeHtml\(title\)/);
    expect(body, 'meta must be escaped').toMatch(/escapeHtml\(meta\)/);
  });

  it('subscribes to chrome.storage.onChanged for activityLog', () => {
    // Real-time updates depend on this subscription. If someone
    // removes it, the notification badge would silently stop
    // updating.
    expect(src).toMatch(/chrome\.storage\.onChanged\.addListener/);
    expect(src).toMatch(/changes\.activityLog/);
  });

  it('notifNotableEvents filters to high + medium severity', () => {
    const fn = src.match(/function\s+notifNotableEvents\s*\(\)\s*\{[\s\S]*?\n\s{2}\}/);
    expect(fn, 'notifNotableEvents() must exist').toBeTruthy();
    const body = fn[0];
    expect(body).toMatch(/severity\s*===\s*['"]high['"]/);
    expect(body).toMatch(/severity\s*===\s*['"]medium['"]/);
  });

  it('hides the badge via the [hidden] attribute (CSS display:none !important is present)', () => {
    const css = readSource('dashboard.css');
    expect(css).toMatch(/\.notif-badge\[hidden\]\s*\{[^}]*display\s*:\s*none\s*!important/);
  });
});