(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const state = {
    domain: '',
    profile: null,
    diagnostics: null,
    settings: {}
  };

  function showMessage(message, error = false) {
    const el = $('message');
    el.textContent = message || '';
    el.dataset.error = error ? '1' : '0';
  }

  function normalizeHost(raw) {
    try {
      const u = new URL(raw);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
      return u.hostname.toLowerCase().replace(/\.$/, '');
    } catch {
      return '';
    }
  }

  function send(message) {
    return chrome.runtime.sendMessage(message).then(result => {
      if (!result?.ok) throw new Error(result?.error || 'Request failed');
      return result;
    });
  }

  async function activeDomain() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return normalizeHost(tabs[0]?.url || '');
  }

  function renderProfile() {
    const profile = state.profile;
    const enabled = Boolean(profile?.protected === true && profile?.mode === 'fortress');
    $('profileState').textContent = profile
      ? `${enabled ? 'Fortress enabled' : 'Protected profile exists but is inactive'} · ${profile.blockedDestinationDomains?.length || 0} blocked destinations`
      : 'No profile for this site';
    $('toggle').textContent = enabled ? 'Disable Fortress' : 'Enable Fortress';
    $('toggle').disabled = !state.domain;

    const list = $('blockedList');
    list.textContent = '';
    const blocked = Array.isArray(profile?.blockedDestinationDomains)
      ? profile.blockedDestinationDomains
      : [];
    if (blocked.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'muted';
      empty.textContent = 'No explicit destination blocks.';
      list.appendChild(empty);
      return;
    }
    for (const host of blocked) {
      const item = document.createElement('div');
      item.className = 'item';
      const label = document.createElement('span');
      label.textContent = host;
      const button = document.createElement('button');
      button.textContent = 'Remove';
      button.addEventListener('click', () => removeBlock(host));
      item.append(label, button);
      list.appendChild(item);
    }
  }

  async function refresh() {
    try {
      showMessage('Refreshing…');
      state.domain = await activeDomain();
      $('domain').textContent = state.domain || 'Unsupported page';
      if (!state.domain) {
        state.profile = null;
        renderProfile();
        $('state').textContent = 'Idle';
        return;
      }

      const [profileResult, diagResult, settingsResult] = await Promise.all([
        send({ type: 'get-profile', domain: state.domain }),
        send({ type: 'get-diagnostics' }),
        send({ type: 'get-settings' })
      ]);
      state.profile = profileResult.profile;
      state.diagnostics = diagResult.diagnostics;
      state.settings = settingsResult.settings || {};
      $('resolver').textContent = state.settings.resolverEnabled === true ? 'ON' : 'OFF';
      $('dnrCount').textContent = String(state.diagnostics.dnrRuleCount);
      $('graphCount').textContent = String(state.diagnostics.graphNodeCount);
      $('profileCount').textContent = String(state.diagnostics.profileCount);
      $('state').textContent = 'Ready';
      renderProfile();
      showMessage('');
    } catch (err) {
      $('state').textContent = 'Error';
      showMessage(err.message, true);
    }
  }

  async function toggleProfile() {
    if (!state.domain) return;
    try {
      const enabled = state.profile?.protected === true && state.profile?.mode === 'fortress';
      const patch = enabled
        ? { protected: false, mode: 'standard' }
        : { protected: true, mode: 'fortress' };
      const result = await send({ type: 'patch-profile', domain: state.domain, patch });
      state.profile = result.profile;
      showMessage(enabled ? 'Fortress disabled.' : 'Fortress enabled.');
      await refresh();
    } catch (err) {
      showMessage(err.message, true);
    }
  }

  async function addBlock() {
    if (!state.domain) return;
    const destination = normalizeHost($('destination').value.trim());
    if (!destination) {
      showMessage('Enter a valid http(s) domain or URL.', true);
      return;
    }
    try {
      const current = Array.isArray(state.profile?.blockedDestinationDomains)
        ? state.profile.blockedDestinationDomains
        : [];
      const blocked = [...new Set([...current, destination])].slice(0, 1000);
      const result = await send({
        type: 'patch-profile',
        domain: state.domain,
        patch: {
          protected: true,
          mode: 'fortress',
          blockedDestinationDomains: blocked
        }
      });
      state.profile = result.profile;
      $('destination').value = '';
      showMessage(`Blocked ${destination}.`);
      await refresh();
    } catch (err) {
      showMessage(err.message, true);
    }
  }

  async function removeBlock(destination) {
    if (!state.domain || !state.profile) return;
    try {
      const blocked = (state.profile.blockedDestinationDomains || []).filter(x => x !== destination);
      const result = await send({
        type: 'patch-profile',
        domain: state.domain,
        patch: { blockedDestinationDomains: blocked }
      });
      state.profile = result.profile;
      showMessage(`Removed ${destination}.`);
      await refresh();
    } catch (err) {
      showMessage(err.message, true);
    }
  }

  $('version').textContent = `v${chrome.runtime.getManifest().version} · Local-first browser shield`;
  $('toggle').addEventListener('click', toggleProfile);
  $('refresh').addEventListener('click', refresh);
  $('addBlock').addEventListener('click', addBlock);
  $('resolver').addEventListener('click', async () => {
    try {
      const next = state.settings.resolverEnabled !== true;
      const result = await send({ type: 'patch-settings', patch: { resolverEnabled: next } });
      state.settings = result.settings || state.settings;
      $('resolver').textContent = next ? 'ON' : 'OFF';
      showMessage(next ? 'Safe Redirect Resolver enabled.' : 'Safe Redirect Resolver disabled.');
    } catch (err) {
      showMessage(err.message, true);
    }
  });

  $('openDashboard').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') }).catch(() => {});
  });

  $('theme').addEventListener('click', async () => {
    const current = (await chrome.storage.local.get('theme')).theme || 'dark';
    const next = current === 'light' ? 'dark' : 'light';
    await chrome.storage.local.set({ theme: next });
    document.body.dataset.theme = next;
  });

  $('destination').addEventListener('keydown', event => {
    if (event.key === 'Enter') addBlock();
  });
  chrome.storage.local.get('theme').then(({ theme = 'dark' }) => { document.body.dataset.theme = theme; });
  refresh();
})();
