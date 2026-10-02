/* Relay admin: small progressive enhancements. Every form works without this
   file; it adds copy buttons, confirmations, auto-submitting filters, tabs,
   the log filter panel opening on wide screens and the client IP check on the
   System page. No inline scripts (CSP 'self'). */
(function () {
  'use strict';

  function closest(target, selector) {
    return target instanceof Element ? target.closest(selector) : null;
  }

  function query(selector) {
    try {
      return selector ? document.querySelector(selector) : null;
    } catch (e) {
      return null;
    }
  }

  // Copy buttons: <button type="button" data-copy="#id">Copy</button>

  // The Clipboard API can refuse (no permission, document not focused); the
  // older execCommand route still works in many of those cases.
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).catch(function () {
        return legacyCopy(text);
      });
    }
    return legacyCopy(text);
  }

  function legacyCopy(text) {
    return new Promise(function (resolve, reject) {
      var buffer = document.createElement('textarea');
      buffer.value = text;
      buffer.setAttribute('readonly', '');
      buffer.className = 'copy-buffer';
      document.body.appendChild(buffer);
      buffer.select();
      var ok = false;
      try {
        ok = document.execCommand('copy');
      } catch (e) {
        ok = false;
      }
      document.body.removeChild(buffer);
      if (ok) resolve();
      else reject(new Error('copy failed'));
    });
  }

  function selectContents(el) {
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
      el.focus();
      el.select();
      return;
    }
    var range = document.createRange();
    range.selectNodeContents(el);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }

  function showButtonFeedback(btn, text) {
    if (!btn.hasAttribute('data-label')) btn.setAttribute('data-label', btn.textContent);
    btn.setAttribute('aria-live', 'polite');
    btn.textContent = text;
    window.clearTimeout(btn.relayTimer);
    btn.relayTimer = window.setTimeout(function () {
      btn.textContent = btn.getAttribute('data-label');
    }, 2000);
  }

  function handleCopy(btn) {
    var target = query(btn.getAttribute('data-copy'));
    if (!target) return;
    var isField = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement;
    var text = (isField ? target.value : target.textContent).trim();
    copyText(text).then(
      function () {
        showButtonFeedback(btn, 'Copied');
      },
      function () {
        // Leave the text selected so Ctrl+C / long-press still works.
        if (!target.hidden) selectContents(target);
        showButtonFeedback(btn, 'Press Ctrl+C to copy');
      }
    );
  }

  // Client IP check (System page): asks /admin/system/ip-check once plainly and
  // once with a forged X-Forwarded-For. If the forged address comes back, the
  // relay trusts a header any client can send.

  var PROBE_IP = '198.51.100.77';

  function handleIpCheck(btn) {
    var url = btn.getAttribute('data-ip-check') || '/admin/system/ip-check';
    var out = query(btn.getAttribute('data-target') || '#ip-check-result');

    function show(state, text) {
      if (!out) return;
      out.textContent = text;
      out.setAttribute('data-state', state);
    }

    function ask(extraHeaders) {
      var headers = { Accept: 'application/json' };
      Object.keys(extraHeaders || {}).forEach(function (k) {
        headers[k] = extraHeaders[k];
      });
      return fetch(url, { headers: headers, credentials: 'same-origin', cache: 'no-store' }).then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      });
    }

    btn.disabled = true;
    show('pending', 'Checking…');
    ask()
      .then(function (plain) {
        return ask({ 'X-Forwarded-For': PROBE_IP }).then(function (forged) {
          if (forged && forged.ip === PROBE_IP) {
            show('bad', 'Spoofable — lower TRUST_PROXY. A client-supplied X-Forwarded-For header was trusted.');
          } else if (!plain || plain.ip === null || plain.ip === undefined) {
            show('warn', 'Client IP unavailable — check TRUST_PROXY.');
          } else {
            show('ok', 'OK — your IP is ' + plain.ip + ' and the forged header was ignored.');
          }
        });
      })
      .catch(function () {
        show('warn', 'The check failed. Reload the page (you may need to sign in again) and try again.');
      })
      .then(function () {
        btn.disabled = false;
      });
  }

  document.addEventListener('click', function (e) {
    var copyBtn = closest(e.target, '[data-copy]');
    if (copyBtn) {
      e.preventDefault();
      handleCopy(copyBtn);
      return;
    }
    var ipBtn = closest(e.target, '[data-ip-check]');
    if (ipBtn) {
      e.preventDefault();
      handleIpCheck(ipBtn);
    }
  });

  // <input data-confirm-if-changed="Question?"> counts as changed when it differs
  // from its baseline: data-confirm-baseline when present ("1"/"0" for a
  // checkbox or radio, else a value), otherwise the state the page was loaded
  // with (defaultChecked / defaultValue).
  function inputChanged(input) {
    var hasBaseline = input.hasAttribute('data-confirm-baseline');
    var baseline = input.getAttribute('data-confirm-baseline');
    if (input.type === 'checkbox' || input.type === 'radio') {
      return input.checked !== (hasBaseline ? baseline === '1' : input.defaultChecked);
    }
    return input.value !== (hasBaseline ? baseline : input.defaultValue);
  }

  // <form data-confirm="Question?"> asks before submitting. An input with
  // data-confirm-if-changed asks its question before its form is submitted with
  // that input changed. Declining any question cancels the submit.
  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (!(form instanceof HTMLFormElement) || e.defaultPrevented) return;
    if (form.hasAttribute('data-confirm') && !window.confirm(form.getAttribute('data-confirm') || 'Are you sure?')) {
      e.preventDefault();
      return;
    }
    var asked = [];
    var fields = form.elements;
    for (var i = 0; i < fields.length; i++) {
      var input = fields[i];
      if (!(input instanceof HTMLInputElement) || !input.hasAttribute('data-confirm-if-changed')) continue;
      if (input.disabled || !inputChanged(input)) continue;
      var question = input.getAttribute('data-confirm-if-changed') || 'Are you sure?';
      if (asked.indexOf(question) !== -1) continue;
      asked.push(question);
      if (!window.confirm(question)) {
        e.preventDefault();
        return;
      }
    }
  });

  // <select data-autosubmit> submits its form on change.
  document.addEventListener('change', function (e) {
    var el = e.target;
    if (!(el instanceof HTMLSelectElement) || !el.hasAttribute('data-autosubmit') || !el.form) return;
    if (typeof el.form.requestSubmit === 'function') el.form.requestSubmit();
    else el.form.submit();
  });

  // Tabs: [data-tabs] container with button.tab[data-tab="<panelId>"]; panels are
  // [data-tab-panel][id]. The server renders the first panel visible and hides
  // the others, so the content is all there without JavaScript.

  function initTabs(container) {
    var tabs = Array.prototype.slice.call(container.querySelectorAll('button.tab[data-tab]'));
    if (!tabs.length) return;
    tabs[0].parentElement.setAttribute('role', 'tablist');

    tabs.forEach(function (tab) {
      var panelId = tab.getAttribute('data-tab');
      var panel = document.getElementById(panelId);
      if (!tab.id) tab.id = 'tab-' + panelId;
      tab.setAttribute('type', 'button');
      tab.setAttribute('role', 'tab');
      tab.setAttribute('aria-controls', panelId);
      if (panel) {
        panel.setAttribute('role', 'tabpanel');
        panel.setAttribute('aria-labelledby', tab.id);
        if (!panel.hasAttribute('tabindex')) panel.setAttribute('tabindex', '0');
      }
    });

    function select(active, moveFocus) {
      tabs.forEach(function (tab) {
        var on = tab === active;
        tab.classList.toggle('tab-active', on);
        tab.setAttribute('aria-selected', on ? 'true' : 'false');
        tab.tabIndex = on ? 0 : -1;
        var panel = document.getElementById(tab.getAttribute('data-tab'));
        if (panel) panel.hidden = !on;
      });
      if (moveFocus) active.focus();
    }

    var initial =
      tabs.filter(function (t) {
        return t.classList.contains('tab-active');
      })[0] || tabs[0];
    select(initial, false);

    container.addEventListener('click', function (e) {
      var tab = closest(e.target, 'button.tab[data-tab]');
      if (tab && tabs.indexOf(tab) !== -1) select(tab, false);
    });

    container.addEventListener('keydown', function (e) {
      var i = tabs.indexOf(document.activeElement);
      if (i === -1) return;
      var next = null;
      if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabs.length - 1;
      if (next === null) return;
      e.preventDefault();
      select(tabs[next], true);
    });
  }

  Array.prototype.forEach.call(document.querySelectorAll('[data-tabs]'), initTabs);

  // <details data-open-wide> (the log filters) opens on load on screens at least
  // 720px wide. On phones it stays as the server rendered it: open only when a
  // filter is set, so the results are on the first screen.
  if (window.matchMedia && window.matchMedia('(min-width: 720px)').matches) {
    Array.prototype.forEach.call(document.querySelectorAll('details[data-open-wide]'), function (d) {
      d.open = true;
    });
  }
})();
