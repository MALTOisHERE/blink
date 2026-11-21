// ── View page: reveal flow ───────────────────────────────────────────────────
// Drives view.html, the page a recipient lands on from a shared link. Reads
// K1 from the URL fragment and keeps it local - only its SHA-256 hash is
// ever sent to the server, never K1 itself (see hashK1() below). Calls
// GET /api/secret/:id, walks through whatever the server asks for next (a
// passphrase, an email OTP), and once it releases K2, decrypts entirely
// client-side via clientDecrypt() - the server never sees the plaintext.
(() => {
  const UUID_RE  = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const K1_B64_RE = /^[A-Za-z0-9+/]{43}=$/;

  function fromB64(str) {
    const bin = atob(str);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }

  function toB64(bytes) {
    let str = '';
    for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str);
  }

  // SHA-256(K1) — sent to the server instead of K1 itself, so K1 never
  // crosses the network at all. Mirrors app.js's hashK1() at creation; the
  // server just compares the two hashes directly, never seeing K1.
  async function hashK1(k1B64) {
    const digest = await crypto.subtle.digest('SHA-256', fromB64(k1B64));
    return toB64(new Uint8Array(digest));
  }

  // The actual decrypt — this is the one place in the whole app where a
  // secret's plaintext comes into existence, and it happens here, in the
  // recipient's own browser, not on the server. The server only ever hands
  // back ciphertext and K2; K1 never left this browser (see init() below).
  // K = K1 XOR K2, same as the split performed at creation in app.js.
  async function clientDecrypt(ciphertextB64, ivB64, k1B64, k2B64) {
    const k1 = fromB64(k1B64);
    const k2 = fromB64(k2B64);
    const keyBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) keyBytes[i] = k1[i] ^ k2[i];
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const iv  = fromB64(ivB64);
    const ctWithTag = fromB64(ciphertextB64);
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ctWithTag);
    return new Uint8Array(plainBuf);
  }

  function setState(id) {
    document.querySelectorAll('.view-state').forEach(el => { el.classList.remove('active'); });
    document.getElementById(id).classList.add('active');
  }

  function showExpired(title, msg) {
    document.getElementById('expired-title').textContent = title;
    document.getElementById('expired-msg').textContent   = msg;
    setState('state-expired');
  }

  function viewsLeftLabel(viewsLeft) {
    return `Can still be viewed ${viewsLeft} more time${viewsLeft === 1 ? '' : 's'} before it is destroyed`;
  }

  function showFile(bytes, filename, mimetype, viewsLeft = 0) {
    document.getElementById('file-reveal-name').textContent = filename;
    if (viewsLeft > 0) {
      document.getElementById('file-notice-text').textContent = viewsLeftLabel(viewsLeft);
    }
    setState('state-file');

    document.getElementById('btn-download-file').onclick = () => {
      const blob = new Blob([bytes], { type: mimetype });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    };
  }

  function showSecret(plaintext, viewsLeft = 0) {
    document.getElementById('secret-text').value = plaintext;
    if (viewsLeft > 0) {
      document.getElementById('secret-notice-text').textContent = viewsLeftLabel(viewsLeft) + '.';
    }
    setState('state-secret');

    // Defined once here rather than inside copyBtn.onclick, so calling
    // showSecret() again (e.g. after a multi-view reveal) doesn't rebuild
    // this string every time for no reason.
    const copyBtn = document.getElementById('btn-copy-secret');
    const COPY_HTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy to Clipboard`;

    copyBtn.onclick = () => {
      navigator.clipboard.writeText(plaintext).then(() => {
        copyBtn.textContent = 'Copied!';
        copyBtn.classList.add('copied');
        setTimeout(() => {
          copyBtn.innerHTML = COPY_HTML;
          copyBtn.classList.remove('copied');
        }, 2000);
      }).catch(() => {
        // Clipboard unavailable — select the textarea as fallback
        document.getElementById('secret-text').select();
      });
    };
  }

  async function revealSecret(id, k1B64, auth = {}, onDone = null) {
    try {
      const headers = { 'X-Key-Hash': await hashK1(k1B64) };
      if (auth.otp)        headers['X-OTP']        = auth.otp;
      if (auth.passphrase) headers['X-Passphrase'] = encodeURIComponent(auth.passphrase);
      const res = await fetch(`/api/secret/${id}`, { headers });

      if (res.status === 403) {
        const data = await res.json();
        if (data.error === 'passphrase_required') {
          setState('state-passphrase');
          setupPassphrase(id, k1B64, auth, onDone);
          return;
        }
        if (data.error === 'invalid_passphrase') {
          setState('state-passphrase');
          const errEl = document.getElementById('passphrase-error');
          errEl.textContent = data.attemptsLeft === 1
            ? 'Invalid passphrase. 1 attempt remaining.'
            : `Invalid passphrase. ${data.attemptsLeft} attempts remaining.`;
          errEl.classList.remove('hidden');
          const passInput = document.getElementById('passphrase-view-input');
          passInput.value = '';
          passInput.focus();
          setupPassphrase(id, k1B64, auth, onDone);
          return;
        }
        if (data.error === 'otp_required') {
          setState('state-otp');
          setupOTP(id, k1B64, auth, onDone);
          return;
        }
        if (data.error === 'invalid_otp') {
          setState('state-otp');
          const errEl = document.getElementById('otp-error');
          errEl.textContent = data.attemptsLeft === 1
            ? 'Invalid code. 1 attempt remaining.'
            : `Invalid code. ${data.attemptsLeft} attempts remaining.`;
          errEl.classList.remove('hidden');
          document.getElementById('otp-input').value = '';
          document.getElementById('otp-input').focus();
          setupOTP(id, k1B64, auth, onDone);
          return;
        }
      }
      if (res.status === 404) {
        onDone?.();
        showExpired('Secret Not Found', 'This secret has already been viewed, has expired, or the link is invalid. Ask the sender to create a new one.');
        return;
      }
      if (res.status === 410) {
        onDone?.();
        const data = await res.json().catch(() => ({}));
        if (data.error === 'too_many_attempts') {
          showExpired('Secret Destroyed', 'Too many incorrect attempts. The secret has been permanently deleted for security.');
        } else {
          showExpired('Link Expired', 'This link has expired. Ask the sender to create a fresh link.');
        }
        return;
      }
      if (res.status === 429) {
        showExpired('Too Many Requests', 'You have made too many requests. Please wait a moment and try again.');
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const data = await res.json();
      const viewsLeft = typeof data.viewsLeft === 'number' ? data.viewsLeft : 0;
      if (viewsLeft <= 0) onDone?.();

      // The server already verified this request holds the real K1 (that's
      // what let it release K2 at all) - decrypt happens here, client-side,
      // never on the server. See clientDecrypt() above.
      const plainBytes = await clientDecrypt(data.ciphertext, data.iv, k1B64, data.k2);
      if (data.isFile) {
        showFile(plainBytes, data.filename, data.mimetype, viewsLeft);
      } else {
        showSecret(new TextDecoder().decode(plainBytes), viewsLeft);
      }
    } catch (err) {
      console.error('[Blink] failed to reveal secret:', err);
      onDone?.();
      showExpired('Something Went Wrong', 'Could not retrieve or decrypt the secret. The link may be malformed or have been tampered with.');
    }
  }

  function setupPassphrase(id, k1B64, auth = {}, onDone = null) {
    const btn   = document.getElementById('btn-passphrase-submit');
    const input = document.getElementById('passphrase-view-input');
    input.focus();
    // revealSecret() re-calls setupPassphrase() on every wrong attempt, so the
    // button keeps picking up a fresh listener each time; cloning it first
    // drops any listener(s) from a previous attempt instead of stacking more
    // on top (which would fire the same submit multiple times per click).
    const clone = btn.cloneNode(true);
    btn.parentNode.replaceChild(clone, btn);
    clone.addEventListener('click', () => {
      const passphrase = input.value;
      if (!passphrase) return;
      document.getElementById('passphrase-error').classList.add('hidden');
      setState('state-loading');
      revealSecret(id, k1B64, { ...auth, passphrase }, onDone);
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') clone.click();
    }, { once: true });

    // Same clone-to-avoid-duplicate-listeners trick as the submit button
    // above, since this function re-runs on every wrong attempt too.
    const toggle = document.getElementById('passphrase-view-toggle');
    const toggleClone = toggle.cloneNode(true);
    toggle.parentNode.replaceChild(toggleClone, toggle);
    toggleClone.addEventListener('click', () => {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      toggleClone.setAttribute('aria-pressed', String(show));
      toggleClone.setAttribute('aria-label', show ? 'Hide passphrase' : 'Show passphrase');
    });
  }

  function setupOTP(id, k1B64, auth = {}, onDone = null) {
    const btn   = document.getElementById('btn-otp-submit');
    const input = document.getElementById('otp-input');
    input.focus();
    // Same reset-the-listener reason as setupPassphrase() above.
    const clone = btn.cloneNode(true);
    btn.parentNode.replaceChild(clone, btn);
    clone.addEventListener('click', () => {
      const otp = input.value.trim();
      if (otp.length !== 6) return;
      document.getElementById('otp-error').classList.add('hidden');
      setState('state-loading');
      revealSecret(id, k1B64, { ...auth, otp }, onDone);
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') clone.click();
    }, { once: true });
  }

  function init() {
    const pathParts = window.location.pathname.split('/');
    const id        = pathParts[pathParts.length - 1];
    const SESS_KEY  = `blink_k1_${id}`;

    // Read K1 from URL hash. If the page was refreshed (hash already stripped),
    // fall back to sessionStorage so OTP users don't lose access mid-flow.
    let k1B64 = decodeURIComponent(window.location.hash.slice(1));
    if (k1B64 && K1_B64_RE.test(k1B64)) {
      try { sessionStorage.setItem(SESS_KEY, k1B64); } catch {}
      history.replaceState(null, '', window.location.pathname);
    } else {
      try { k1B64 = sessionStorage.getItem(SESS_KEY) || ''; } catch {}
    }

    if (!id || !UUID_RE.test(id)) {
      showExpired('Invalid Link', 'The link format is invalid.');
      return;
    }

    if (!k1B64 || !K1_B64_RE.test(k1B64)) {
      showExpired('Invalid Link', 'This link is missing or has a corrupted key.');
      return;
    }

    const clearK1 = () => { try { sessionStorage.removeItem(SESS_KEY); } catch {} };

    setState('state-reveal');

    document.getElementById('btn-reveal').addEventListener('click', () => {
      setState('state-loading');
      revealSecret(id, k1B64, {}, clearK1);
    }, { once: true });
  }

  init();
})();
