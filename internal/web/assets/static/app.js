// smbdeck: progressive enhancement only. Every page works without this file:
// forms post, confirmations have pages of their own, the folder picker goes
// through the server, passwords are generated server-side when left empty.
// No dependency, no build step.
(() => {
  'use strict';
  const doc = document;
  doc.documentElement.classList.add('js');

  // Confirmations: a link to the confirmation page opens the same form in a
  // dialog instead.
  doc.addEventListener('click', (event) => {
    const link = event.target.closest('a[data-dialog]');
    if (link) {
      const dialog = doc.getElementById(link.dataset.dialog);
      if (dialog instanceof HTMLDialogElement && dialog.showModal) {
        event.preventDefault();
        if (!dialog.open) dialog.showModal();
      }
      return;
    }
    const close = event.target.closest('[data-close]');
    if (close) close.closest('dialog')?.close();
  });

  // Copy buttons copy the <code> next to them. The clipboard API exists only
  // in secure contexts (HTTPS, localhost); elsewhere the buttons stay hidden
  // and the text is selected with one click (user-select: all).
  if (navigator.clipboard && window.isSecureContext) {
    for (const button of doc.querySelectorAll('[data-copy]')) {
      button.hidden = false;
      button.addEventListener('click', async () => {
        const code = button.parentElement.querySelector('code');
        if (!code) return;
        try {
          await navigator.clipboard.writeText(code.textContent.trim());
          button.setAttribute('data-copied', '');
          setTimeout(() => button.removeAttribute('data-copied'), 1600);
        } catch {
          // Permission refused: the text stays selectable.
        }
      });
    }
  }

  // Show or hide a password field.
  const revealButtons = new Map();
  for (const button of doc.querySelectorAll('[data-reveal]')) {
    const input = doc.getElementById(button.dataset.reveal);
    if (!input) continue;
    revealButtons.set(input.id, button);
    button.hidden = false;
    button.addEventListener('click', () => {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      button.setAttribute('aria-pressed', String(show));
    });
  }

  // Password generator: 20 characters from 56 (about 116 bits), uniform
  // (rejection sampling), the same alphabet as the server's.
  const alphabet = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const generate = () => {
    const limit = 256 - (256 % alphabet.length);
    const out = [];
    while (out.length < 20) {
      for (const byte of crypto.getRandomValues(new Uint8Array(32))) {
        if (byte < limit && out.length < 20) out.push(alphabet[byte % alphabet.length]);
      }
    }
    return [0, 5, 10, 15].map((i) => out.slice(i, i + 5).join('')).join('-');
  };
  if (window.crypto && crypto.getRandomValues) {
    for (const button of doc.querySelectorAll('[data-generate]')) {
      const input = doc.getElementById(button.dataset.generate);
      if (!input) continue;
      button.hidden = false;
      button.addEventListener('click', () => {
        const password = generate();
        input.value = password;
        input.type = 'text';
        revealButtons.get(input.id)?.setAttribute('aria-pressed', 'true');
        const confirm = button.dataset.confirm && doc.getElementById(button.dataset.confirm);
        if (confirm) {
          confirm.value = password;
          confirm.type = 'text';
        }
        input.focus();
        input.select();
      });
    }
  }

  // Share form: root choice, folder picker, Time Machine fields.
  const form = doc.querySelector('[data-share-form]');
  if (form) {
    const path = form.querySelector('[data-path-input]');
    const prefix = form.querySelector('[data-root-prefix]');
    const lists = form.querySelectorAll('[data-picker-root]');
    const root = () => form.querySelector('[data-root-choice]:checked')?.value ?? '';
    const clean = (value) => value.trim().replace(/^\/+|\/+$/g, '');
    const sync = () => {
      const current = root();
      if (prefix && current) prefix.textContent = `${current}/`;
      for (const list of lists) list.toggleAttribute('data-inactive', list.dataset.pickerRoot !== current);
      for (const button of form.querySelectorAll('[data-folder]')) {
        const chosen = button.dataset.root === current && button.dataset.folder === clean(path.value);
        button.setAttribute('aria-pressed', String(chosen));
      }
    };
    form.addEventListener('change', (event) => {
      if (event.target.matches('[data-root-choice]')) sync();
    });
    path?.addEventListener('input', sync);
    form.addEventListener('click', (event) => {
      const button = event.target.closest('[data-folder]');
      if (!button || !path) return;
      // Without JavaScript, the button posts the form and the server fills
      // the folder in; here it is done in place.
      event.preventDefault();
      for (const radio of form.querySelectorAll('[data-root-choice]')) {
        if (radio.value === button.dataset.root) radio.checked = true;
      }
      path.value = button.dataset.folder;
      sync();
    });
    const tm = form.querySelector('[data-tm-toggle]');
    const tmFields = form.querySelector('[data-tm-fields]');
    if (tm && tmFields) {
      const syncTM = () => tmFields.toggleAttribute('data-off', !tm.checked);
      tm.addEventListener('change', syncTM);
      syncTM();
    }
    sync();
  }

  // Live agent status: "Applying…" turns into "Applied" without a reload.
  // Polling stops after a quarter of an hour without any gesture (it does not
  // keep the session alive anyway) and resumes with the next one.
  const statuses = doc.querySelectorAll('[data-status]');
  if (statuses.length && window.fetch) {
    const url = statuses[0].dataset.status;
    const idleLimit = 15 * 60 * 1000;
    let lastGesture = Date.now();
    let sleeping = false;
    let delay = 1500;
    const wake = () => {
      lastGesture = Date.now();
      if (sleeping) {
        sleeping = false;
        setTimeout(tick, 0);
      }
    };
    for (const type of ['pointerdown', 'keydown', 'wheel', 'touchstart']) {
      doc.addEventListener(type, wake, { passive: true });
    }
    const tick = async () => {
      if (Date.now() - lastGesture > idleLimit) {
        sleeping = true;
        return;
      }
      if (!doc.hidden) {
        try {
          const response = await fetch(url, { headers: { Accept: 'application/json' }, cache: 'no-store' });
          if (response.status === 401) return;
          if (response.ok) {
            const status = await response.json();
            for (const element of statuses) {
              if (element.dataset.state === status.state) continue;
              element.dataset.state = status.state;
              element.className = `status status--${status.state}`;
              element.querySelector('[data-status-label]').textContent = status.label;
              element.setAttribute('data-changed', '');
            }
            for (const element of doc.querySelectorAll('[data-status-applied]')) element.textContent = String(status.applied);
            for (const element of doc.querySelectorAll('[data-status-desired]')) element.textContent = String(status.desired);
            delay = status.state === 'pending' || status.state === 'unknown' ? 1500 : 8000;
          }
        } catch {
          delay = 8000;
        }
      }
      setTimeout(tick, delay);
    };
    setTimeout(tick, 500);
  }
})();
