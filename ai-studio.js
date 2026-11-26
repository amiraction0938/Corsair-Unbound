/* ============================================================
   CORSAIR UNBOUND — AI SCRIPT STUDIO CONTROLLER (v1.13.0)
   ============================================================ */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const send = (msg) => chrome.runtime.sendMessage(msg);

  const state = {
    originTabId: null,
    pageContext: null,
    providers: [],
    defaultProviderId: '',
    settings: null,
    history: { versions: [], index: -1 },
    lastValidation: null,
    lastTestError: '',
    activeRequestId: ''
  };

  async function applyThemeAndLang() {
    try {
      const res = await chrome.storage.local.get(['theme', 'language']);
      const theme = res.theme || 'amethyst';
      document.documentElement.setAttribute('data-theme', theme);
      document.body.dataset.theme = theme;
      if (typeof CorsairI18n !== 'undefined') {
        await CorsairI18n.init(res.language);
        CorsairI18n.applyDOM(document);
      }
    } catch {}
  }

  function updateProviderBadge() {
    const selId = $('studioProvider').value;
    const p = state.providers.find(x => x.id === selId);
    const badge = $('providerLocalityBadge');
    const banner = $('cloudPrivacyBanner');
    if (!p) return;
    const loc = p.locality || 'local';
    badge.className = `locality-badge ${loc}`;
    badge.textContent = loc.toUpperCase();
    if (loc === 'cloud') {
      banner.hidden = false;
      $('cloudProviderHost').textContent = `${p.name} (${p.baseUrl})`;
    } else {
      banner.hidden = true;
    }
    if (!$('studioModel').value || $('studioModel').dataset.autoFilled === '1') {
      $('studioModel').value = p.model || p.defaultModel || '';
      $('studioModel').dataset.autoFilled = '1';
    }
  }

  async function loadOriginContext() {
    if (!Number.isInteger(state.originTabId)) {
      $('originBanner').textContent = 'No originating web tab bound (standalone mode).';
      return;
    }
    const r = await send({
      type: 'ai-collect-context',
      tabId: state.originTabId,
      includeQuery: $('includeQueryChk').checked
    });
    if (r && r.ok && r.context) {
      state.pageContext = r.context;
      $('originBanner').textContent = `Tab #${state.originTabId} — ${r.context.origin || r.context.canonicalUrl} (${r.context.title || 'Untitled'})`;
      $('contextPreview').textContent = JSON.stringify(r.context, null, 2);
      $('testOnTabBtn').disabled = !$('codeEditor').value.trim();
    } else {
      $('originBanner').textContent = `Tab #${state.originTabId} — ${(r && r.error) || 'Context unavailable'}`;
      $('contextPreview').textContent = (r && r.error) || 'Could not collect page context.';
    }
  }

  function pushHistory(code, prompt, note) {
    const trimmed = state.history.versions.slice(0, state.history.index + 1);
    trimmed.push({ code, prompt, note, at: Date.now() });
    state.history = { versions: trimmed, index: trimmed.length - 1 };
    updateHistoryButtons();
  }

  function updateHistoryButtons() {
    $('undoVerBtn').disabled = state.history.index <= 0;
    $('redoVerBtn').disabled = state.history.index >= state.history.versions.length - 1;
    $('versionBadge').textContent = state.history.versions.length ? `v${state.history.index + 1}/${state.history.versions.length}` : 'v0';
    const hasCode = Boolean($('codeEditor').value.trim());
    $('iterateBtn').disabled = !hasCode;
    $('saveDraftBtn').disabled = !hasCode;
    $('saveEnableBtn').disabled = !hasCode;
    $('discardBtn').disabled = !hasCode;
    $('testOnTabBtn').disabled = !hasCode || !Number.isInteger(state.originTabId);
  }

  function renderValidation(val, liveExec) {
    state.lastValidation = val;
    const stagesBox = $('validationStages');
    const permBox = $('permissionsBox');
    stagesBox.textContent = '';
    permBox.textContent = '';
    if (!val) return;

    const addStage = (title, status, cls, lines) => {
      const div = document.createElement('div');
      div.className = `stage-item ${cls}`;
      const head = document.createElement('div');
      head.className = 'stage-head';
      const s1 = document.createElement('span');
      s1.textContent = String(title || '');
      const s2 = document.createElement('span');
      s2.textContent = String(status || '');
      head.appendChild(s1);
      head.appendChild(s2);
      div.appendChild(head);
      for (const line of lines) {
        const p = document.createElement('div');
        p.className = 'finding-item';
        p.textContent = line;
        div.appendChild(p);
      }
      stagesBox.appendChild(div);
    };

    const st = val.stages;
    addStage(
      '1. Syntax Validation',
      st.syntax.ok ? 'PASS' : 'FAIL',
      st.syntax.ok ? 'ok' : 'fail',
      st.syntax.ok ? ['Pure-JS lexical & delimiter checks passed.'] : st.syntax.errors.map(e => `Line ${e.line}: ${e.message}`)
    );
    addStage(
      '2. Metadata & Scope',
      st.metadata.ok ? 'PASS' : 'FAIL',
      st.metadata.ok ? 'ok' : 'fail',
      st.metadata.ok ? [`${val.meta?.name || 'Unnamed'} (${val.permissions.runAt})`] : st.metadata.errors
    );
    addStage(
      '3. Static Security Analysis',
      st.staticSecurity.highCount ? `HIGH RISK (${st.staticSecurity.highCount})` : (st.staticSecurity.mediumCount ? `WARN (${st.staticSecurity.mediumCount})` : 'CLEAN'),
      st.staticSecurity.highCount ? 'fail' : (st.staticSecurity.mediumCount ? 'warn' : 'ok'),
      st.staticSecurity.findings.length
        ? st.staticSecurity.findings.map(f => `[${f.severity.toUpperCase()}] ${f.title}: ${f.detail}`)
        : ['No high/medium static security warnings detected.']
    );
    addStage(
      '4. API Compatibility',
      st.apiCompatibility.ok ? 'PASS' : 'WARN',
      st.apiCompatibility.ok ? 'ok' : 'warn',
      st.apiCompatibility.ok ? ['All declared GM APIs are supported by Corsair Unbound.'] : [`Unsupported: ${st.apiCompatibility.unsupportedApis.join(', ')}`]
    );
    const live = liveExec || st.liveExecution;
    addStage(
      '5. Live Tab Execution',
      live.status === 'passed' ? 'INJECTED' : (live.status === 'failed' ? 'ERROR' : 'NOT RUN'),
      live.status === 'passed' ? 'ok' : (live.status === 'failed' ? 'fail' : 'warn'),
      [live.message || 'Click "Test on This Tab" to preview safely.']
    );
    addStage(
      '6. Behavioral Verification',
      'USER CHECK',
      'warn',
      [st.behavioralVerification.message]
    );

    const p = val.permissions;
    const renderGroup = (label, arr) => {
      const row = document.createElement('div');
      const strong = document.createElement('strong');
      strong.textContent = label + ': ';
      row.appendChild(strong);
      if (!arr || !arr.length) {
        const span = document.createElement('span');
        span.className = 'muted';
        span.textContent = 'none';
        row.appendChild(span);
      } else {
        for (const item of arr) {
          const chip = document.createElement('span');
          chip.className = 'perm-chip';
          chip.textContent = item;
          row.appendChild(chip);
        }
      }
      permBox.appendChild(row);
    };
    renderGroup('@match', p.matches);
    renderGroup('@grant', p.grants.length ? p.grants : ['none']);
    renderGroup('@connect', p.connects);
    renderGroup('@require', p.requires);
    renderGroup('Recommended World', [p.recommendedWorld]);
    $('testWorldSelect').value = p.recommendedWorld === 'MAIN' ? 'MAIN' : 'USER_SCRIPT';
  }

  async function runValidation() {
    const code = $('codeEditor').value;
    if (!code.trim()) return;
    const r = await send({ type: 'ai-validate-script', code });
    if (r && r.ok) renderValidation(r.validation);
  }

  async function runGeneration(isIteration = false) {
    const prompt = $('studioPrompt').value.trim();
    if (!prompt) {
      $('genStatus').textContent = 'Enter a description of the userscript first.';
      return;
    }
    const reqId = 'req_' + Date.now().toString(36);
    state.activeRequestId = reqId;
    $('generateBtn').disabled = true;
    $('iterateBtn').disabled = true;
    $('cancelBtn').hidden = false;
    $('genStatus').textContent = 'Generating userscript with selected AI provider…';

    const r = await send({
      type: 'ai-generate-script',
      requestId: reqId,
      providerId: $('studioProvider').value,
      model: $('studioModel').value.trim(),
      prompt,
      templateId: $('studioTemplate').value,
      scopeMode: $('studioScope').value,
      pageContext: $('includeContextChk').checked ? state.pageContext : null,
      previousCode: isIteration ? $('codeEditor').value : '',
      errorReport: isIteration ? state.lastTestError : ''
    });

    state.activeRequestId = '';
    $('generateBtn').disabled = false;
    $('cancelBtn').hidden = true;

    if (!r || !r.ok) {
      $('genStatus').textContent = `Generation failed: ${(r && r.error) || 'Unknown error'}`;
      updateHistoryButtons();
      return;
    }

    $('codeEditor').value = r.code || '';
    pushHistory(r.code || '', prompt, isIteration ? 'Iteration' : 'Initial');
    $('genLatency').textContent = r.latencyMs ? `${r.latencyMs} ms` : '';
    $('genStatus').textContent = `Generated by ${r.providerName}${r.convertedFromTs ? ' (TypeScript converted to JS)' : ''}. Review carefully before testing.`;
    renderValidation(r.validation);
    updateHistoryButtons();
  }

  async function init() {
    await applyThemeAndLang();
    const params = new URLSearchParams(location.search);
    const tabIdParam = Number(params.get('tabId'));
    if (Number.isInteger(tabIdParam) && tabIdParam > 0) state.originTabId = tabIdParam;
    if (params.get('prompt')) $('studioPrompt').value = params.get('prompt');

    const [provRes, setRes, usRes] = await Promise.all([
      send({ type: 'ai-providers-list' }),
      send({ type: 'ai-settings-get' }),
      send({ type: 'us-list' })
    ]);

    if (provRes && provRes.ok) {
      state.providers = provRes.profiles || [];
      state.defaultProviderId = provRes.defaultProfileId || '';
      const sel = $('studioProvider');
      sel.textContent = '';
      for (const p of state.providers) {
        const opt = document.createElement('option');
        opt.value = p.id;
        opt.textContent = `[${(p.locality || 'local').toUpperCase()}] ${p.name}`;
        sel.appendChild(opt);
      }
      const wantedProv = params.get('providerId') || state.defaultProviderId;
      if (wantedProv) sel.value = wantedProv;
      updateProviderBadge();
    }

    if (setRes && setRes.ok) {
      state.settings = setRes.settings;
      const tSel = $('studioTemplate');
      tSel.textContent = '';
      const templates = [...(setRes.builtinTemplates || []), ...((setRes.settings && setRes.settings.customTemplates) || [])];
      for (const t of templates) {
        const opt = document.createElement('option');
        opt.value = t.id;
        opt.textContent = t.name;
        tSel.appendChild(opt);
      }
    }

    if (usRes && usRes.ok && usRes.availability && !usRes.availability.ok) {
      const b = $('availabilityBanner');
      b.hidden = false;
      b.textContent = `User Scripts API disabled: ${usRes.availability.setupInstructions || usRes.availability.message}`;
    }

    await loadOriginContext();
    updateHistoryButtons();
    if (params.get('autoGen') === '1' && $('studioPrompt').value.trim()) {
      runGeneration(false);
    }

    // Events
    $('studioProvider').addEventListener('change', () => {
      $('studioModel').dataset.autoFilled = '1';
      updateProviderBadge();
    });
    $('studioModel').addEventListener('input', () => { $('studioModel').dataset.autoFilled = '0'; });
    $('refreshContextBtn').addEventListener('click', loadOriginContext);
    $('includeQueryChk').addEventListener('change', loadOriginContext);
    $('generateBtn').addEventListener('click', () => runGeneration(false));
    $('iterateBtn').addEventListener('click', () => runGeneration(true));
    $('cancelBtn').addEventListener('click', async () => {
      if (state.activeRequestId) await send({ type: 'ai-cancel-request', requestId: state.activeRequestId });
    });
    $('revalidateBtn').addEventListener('click', runValidation);
    $('codeEditor').addEventListener('input', updateHistoryButtons);

    $('undoVerBtn').addEventListener('click', () => {
      if (state.history.index > 0) {
        state.history.index--;
        $('codeEditor').value = state.history.versions[state.history.index].code;
        updateHistoryButtons();
        runValidation();
      }
    });
    $('redoVerBtn').addEventListener('click', () => {
      if (state.history.index < state.history.versions.length - 1) {
        state.history.index++;
        $('codeEditor').value = state.history.versions[state.history.index].code;
        updateHistoryButtons();
        runValidation();
      }
    });

    $('testOnTabBtn').addEventListener('click', async () => {
      const code = $('codeEditor').value;
      if (!code.trim() || !Number.isInteger(state.originTabId)) return;
      $('testOutput').textContent = 'Running one-time preview on originating tab…';
      $('sendErrorToAiBtn').hidden = true;
      const r = await send({
        type: 'ai-preview-script',
        tabId: state.originTabId,
        code,
        world: $('testWorldSelect').value
      });
      if (r && r.ok) {
        state.lastTestError = '';
        $('testOutput').textContent = `Injected once via ${r.method} in ${r.world} world (tab #${r.tabId}, not registered). Verify behavior on the page.`;
        renderValidation(state.lastValidation, { status: 'passed', message: `One-time preview injected via ${r.method} (${r.world}).` });
      } else {
        state.lastTestError = (r && r.error) || 'Preview execution failed.';
        $('testOutput').textContent = `Preview failed (${r?.method || 'error'}): ${state.lastTestError}`;
        $('sendErrorToAiBtn').hidden = false;
        renderValidation(state.lastValidation, { status: 'failed', message: state.lastTestError });
      }
    });

    $('sendErrorToAiBtn').addEventListener('click', () => {
      $('studioPrompt').value = `Fix this execution error from testing on the target tab:\n${state.lastTestError}`;
      runGeneration(true);
    });

    const saveScript = async (enabled) => {
      const code = $('codeEditor').value;
      if (!code.trim()) return;
      const r = await send({ type: 'us-save', code, enabled });
      if (r && r.ok) {
        $('genStatus').textContent = enabled
          ? 'Saved and enabled in Corsair Userscripts! It will now run automatically on matching navigations.'
          : 'Saved as Draft (disabled) in Corsair Userscripts.';
      } else {
        $('genStatus').textContent = `Save failed: ${(r && r.error) || 'Unknown error'}`;
      }
    };

    $('saveDraftBtn').addEventListener('click', () => saveScript(false));
    $('saveEnableBtn').addEventListener('click', () => saveScript(true));
    $('discardBtn').addEventListener('click', () => {
      $('codeEditor').value = '';
      state.history = { versions: [], index: -1 };
      $('validationStages').textContent = '';
      $('permissionsBox').textContent = '';
      $('genStatus').textContent = 'Discarded draft.';
      updateHistoryButtons();
    });

    $('openDashboardBtn').addEventListener('click', () => send({ type: 'open-dashboard' }));
    $('openProvidersBtn').addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html#ai-providers') });
    });
  }

  init();
})();
