/* Managed guest SSH only. No localStorage, token URLs, CDN fallback or reconnect credentials. */
(() => {
  'use strict';
  const root = document.getElementById('webssh-app');
  if (!root) return;
  const $ = id => document.getElementById(id);
  const connectButton = $('ssh-connect'), disconnectButton = $('ssh-disconnect');
  const authDialog = $('ssh-auth-dialog'), trustDialog = $('ssh-trust-dialog');
  const specialKeys = [...root.querySelectorAll('[data-ssh-key]')];
  let socket = null, connected = false, connecting = false, stopped = false;
  let connectedAt = 0, ping = null, pingCounter = 0, trust = null, resizeTimer;
  let terminal, fit;
  const available = root.dataset.available === 'true';
  const isSecure = location.protocol === 'https:' || ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
  const alert = text => { $('ssh-alert').textContent = text; $('ssh-alert').hidden = !text; };
  const state = (text, kind = '') => { $('ssh-status').textContent = text; $('ssh-status-dot').dataset.state = kind; };
  const clearCredentials = () => {
    for (const id of ['ssh-password', 'ssh-private-key', 'ssh-key-passphrase', 'ssh-key-file']) $(id).value = '';
  };
  function controls() {
    connectButton.disabled = !available || !isSecure || connected || connecting;
    disconnectButton.disabled = !connected && !connecting;
    specialKeys.forEach(button => { button.disabled = !connected; });
    if (terminal) terminal.options.disableStdin = !connected;
  }
  function send(data) {
    if (!socket || socket.readyState !== WebSocket.OPEN) return false;
    if (socket.bufferedAmount > 256 * 1024) { fail('The terminal connection is congested. Reconnect before sending more input.'); return false; }
    socket.send(JSON.stringify(data));
    return true;
  }
  function closeDialogs() {
    if (authDialog.open) authDialog.close();
    if (trustDialog.open) trustDialog.close();
    trust = null;
    clearCredentials();
  }
  function finish(text = 'Disconnected', kind = '') {
    connected = connecting = false;
    ping = null;
    $('ssh-rtt').textContent = 'RTT —';
    $('ssh-duration').textContent = '—';
    controls();
    state(text, kind);
    closeDialogs();
  }
  function disconnect() {
    stopped = true;
    send({type: 'disconnect'});
    if (socket) { socket.close(); socket = null; }
    finish();
  }
  function fail(text) {
    stopped = true;
    if (socket) { socket.close(); socket = null; }
    finish('Connection closed', 'error');
    alert(text);
  }
  function size() {
    if (!terminal) return {cols: 80, rows: 24};
    return {cols: Math.max(2, Math.min(500, terminal.cols)), rows: Math.max(1, Math.min(200, terminal.rows))};
  }
  function resize() {
    if (!fit) return;
    try {
      fit.fit();
      const dimensions = size();
      $('ssh-size').textContent = `${dimensions.cols} × ${dimensions.rows}`;
      if (connected) send({type: 'resize', ...dimensions});
    } catch (_) { /* The element may be hidden during navigation. */ }
  }
  function input(text) {
    if (!connected) return;
    if (new TextEncoder().encode(text).length > 128 * 1024) { alert('Paste is limited to 128 KiB at a time. Paste smaller chunks.'); return; }
    // Split at Unicode code points, preserving surrogate pairs; each chunk is
    // at most 8 KiB UTF-8 and below the server's 16 KiB input/message limit.
    let chunk = '', bytes = 0;
    for (const point of text) {
      const length = new TextEncoder().encode(point).length;
      if (bytes + length > 8192) { send({type: 'input', data: chunk}); chunk = ''; bytes = 0; }
      chunk += point; bytes += length;
    }
    if (chunk) send({type: 'input', data: chunk});
  }
  function probe() {
    if (!connected || ping) return;
    ping = {nonce: String(++pingCounter), started: performance.now()};
    send({type: 'ping', nonce: ping.nonce});
  }
  function chooseAuth() {
    const key = $('ssh-auth-method').value === 'key';
    $('ssh-password-field').hidden = key;
    $('ssh-key-fields').hidden = !key;
    $('ssh-password').disabled = key;
    $('ssh-password').required = !key;
    $('ssh-private-key').disabled = !key;
    $('ssh-private-key').required = key;
    $('ssh-key-passphrase').disabled = !key;
    clearCredentials();
  }
  function safeLink(uri) {
    try { const link = new URL(uri); if (['https:', 'http:'].includes(link.protocol)) window.open(link.href, '_blank', 'noopener,noreferrer'); } catch (_) { /* Ignore unsafe links. */ }
  }
  function trustKey(data) {
    if (typeof data.fingerprint !== 'string' || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(data.fingerprint)) {
      fail('The SSH server returned an invalid host fingerprint.'); return;
    }
    trust = data;
    $('ssh-key-fingerprint').textContent = data.fingerprint;
    $('ssh-key-algorithm').textContent = data.algorithm;
    $('ssh-key-previous').textContent = data.previous || '';
    $('ssh-changed-warning').hidden = !data.changed;
    $('ssh-confirm-changed').checked = false;
    $('ssh-accept-key').disabled = !!data.changed;
    state(data.changed ? 'Host key changed' : 'Verify host key', 'connecting');
    trustDialog.showModal();
    $('ssh-reject-key').focus();
  }
  function onMessage(event) {
    let data;
    try { data = JSON.parse(event.data); } catch (_) { fail('Invalid WebSSH server response.'); return; }
    if (data.type === 'host_key') { trustKey(data); return; }
    if (data.type === 'connected') {
      connected = true; connecting = false; connectedAt = performance.now();
      $('ssh-terminal-placeholder').hidden = true;
      controls(); state('Connected', 'connected'); alert('');
      resize(); terminal.focus(); probe();
    } else if (data.type === 'output' && typeof data.data === 'string') {
      // xterm interprets guest terminal bytes; never put them in HTML.
      terminal.write(data.data);
    } else if (data.type === 'pong' && ping && data.nonce === ping.nonce) {
      $('ssh-rtt').textContent = `RTT ${Math.max(0, Math.round(performance.now() - ping.started))} ms`;
      ping = null;
    } else if (data.type === 'error') {
      fail(typeof data.message === 'string' ? data.message : 'SSH connection failed.');
    } else if (data.type === 'disconnected') {
      stopped = true;
      if (socket) { socket.close(); socket = null; }
      finish();
      alert(data.message || 'The guest SSH session ended.');
    }
  }
  function open(credentials) {
    const endpoint = new URL(root.dataset.socketUrl, location.href);
    if (endpoint.origin !== location.origin) { credentials = null; fail('Only same-origin managed guest connections are allowed.'); return; }
    endpoint.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    stopped = false; connecting = true; connected = false;
    controls(); state('Connecting', 'connecting'); alert('');
    let current;
    try { current = new WebSocket(endpoint); } catch (_) { credentials = null; clearCredentials(); fail('Cannot open the secure WebSSH transport.'); return; }
    socket = current;
    const setupTimer = setTimeout(() => {
      credentials = null;
      if (socket === current && !connected) fail('Connection setup timed out. Check the guest SSH service and try again.');
    }, 100000);
    current.addEventListener('open', () => {
      if (socket !== current) { credentials = null; return; }
      current.send(JSON.stringify({type: 'connect', csrf_token: document.querySelector('meta[name=csrf-token]').content,
        credentials, ...size()}));
      credentials = null;
      clearCredentials();
      authDialog.close();
    });
    current.addEventListener('message', event => { if (socket === current) onMessage(event); });
    current.addEventListener('error', () => {
      if (socket === current) fail('The WebSSH transport could not be opened. Refresh to check VM availability. Use HTTPS and ensure your reverse proxy supports WebSocket upgrades.');
    });
    current.addEventListener('close', event => {
      credentials = null;
      clearTimeout(setupTimer);
      if (socket !== current) return;
      socket = null;
      if (!stopped) { finish('Disconnected', 'error'); alert(event.code === 1009 ? 'WebSSH rejected oversized or excessive pending input. Reconnect and send smaller chunks.' : 'SSH transport closed. The guest keeps running. Reconnect with your guest credentials.'); }
    });
  }
  try {
    if (!window.Terminal || !window.FitAddon || !window.WebLinksAddon) throw new Error('assets');
    terminal = new Terminal({cursorBlink: true, cursorStyle: 'bar', fontFamily: '"JetBrains Mono", monospace',
      fontSize: matchMedia('(max-width: 700px)').matches ? 12 : 13, lineHeight: 1.2, scrollback: 5000,
      linkHandler: {activate: (_event, uri) => safeLink(uri)},
      disableStdin: true, allowProposedApi: false, convertEol: false, screenReaderMode: true,
      theme: {background: '#0c0d14', foreground: '#d4cfe2', cursor: '#b397ff', cursorAccent: '#0c0d14',
        selectionBackground: '#7f5ca655', black: '#292733', red: '#f28f9b', green: '#92d6ad', yellow: '#e4c68f',
        blue: '#9aafff', magenta: '#cba0eb', cyan: '#91d3d7', white: '#ded8ea', brightBlack: '#746c87'}});
    fit = new FitAddon.FitAddon();
    terminal.loadAddon(fit);
    terminal.loadAddon(new WebLinksAddon.WebLinksAddon((_event, uri) => {
      safeLink(uri);
    }));
    terminal.open($('ssh-terminal'));
    terminal.onData(input);
    terminal.onBinary(() => {}); // Legacy binary mouse protocols aren't a host command path.
    const observer = new ResizeObserver(() => { clearTimeout(resizeTimer); resizeTimer = setTimeout(resize, 150); });
    observer.observe($('ssh-terminal'));
    document.fonts.ready.then(resize);
    resize();
  } catch (_) {
    connectButton.disabled = true;
    alert('Local terminal assets could not be loaded. Run npm ci && npm run build:assets, then restart and refresh the panel.');
    return;
  }
  $('ssh-instance-select').addEventListener('change', event => { disconnect(); location.assign(event.target.value); });
  connectButton.addEventListener('click', () => { clearCredentials(); authDialog.showModal(); ($('ssh-auth-method').value === 'key' ? $('ssh-private-key') : $('ssh-password')).focus(); });
  disconnectButton.addEventListener('click', disconnect);
  $('ssh-clear').addEventListener('click', () => {
    terminal.write('\x1b[2J\x1b[H', () => {
      terminal.clear();
      // Flush pending screen-reader announcements as well as visible rows.
      // xterm's clear() alone leaves its asynchronous live-region readback.
      if (terminal.options.screenReaderMode) {
        terminal.options.screenReaderMode = false;
        terminal.options.screenReaderMode = true;
      }
      if (connected) terminal.focus();
    });
  });
  $('ssh-auth-method').addEventListener('change', chooseAuth);
  $('ssh-auth-cancel').addEventListener('click', () => connecting ? disconnect() : authDialog.close());
  $('ssh-auth-back').addEventListener('click', () => connecting ? disconnect() : authDialog.close());
  authDialog.addEventListener('cancel', event => { if (connecting) { event.preventDefault(); disconnect(); } });
  authDialog.addEventListener('close', clearCredentials);
  $('ssh-key-file').addEventListener('change', async event => {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 65536) { event.target.value = ''; alert('Private keys must be no larger than 64 KiB.'); return; }
    try { const text = await file.text(); if (authDialog.open && $('ssh-auth-method').value === 'key' && event.target.files[0] === file) $('ssh-private-key').value = text; } catch (_) { alert('The selected private key could not be read.'); }
  });
  $('ssh-auth-form').addEventListener('submit', event => {
    event.preventDefault();
    if (connecting || connected || !available || !isSecure) return;
    let credentials;
    if ($('ssh-auth-method').value === 'key') {
      const key = $('ssh-private-key').value;
      if (new TextEncoder().encode(key).length > 65536) { alert('Private keys must be no larger than 64 KiB.'); return; }
      credentials = {method: 'key', private_key: key, passphrase: $('ssh-key-passphrase').value};
    } else credentials = {method: 'password', password: $('ssh-password').value};
    open(credentials);
    credentials = null;
    clearCredentials();
  });
  $('ssh-confirm-changed').addEventListener('change', () => { $('ssh-accept-key').disabled = !!trust?.changed && !$('ssh-confirm-changed').checked; });
  $('ssh-accept-key').addEventListener('click', () => {
    if (!trust || (trust.changed && !$('ssh-confirm-changed').checked)) return;
    send({type: 'trust', fingerprint: trust.fingerprint, accept: true, confirm_changed: $('ssh-confirm-changed').checked});
    trustDialog.close(); trust = null;
    state('Authenticating', 'connecting');
  });
  $('ssh-reject-key').addEventListener('click', disconnect);
  trustDialog.addEventListener('cancel', event => { event.preventDefault(); disconnect(); });
  const keys = {interrupt: '\x03', eof: '\x04', tab: '\t', escape: '\x1b', up: '\x1b[A', down: '\x1b[B', left: '\x1b[D', right: '\x1b[C'};
  specialKeys.forEach(button => button.addEventListener('click', () => { input(keys[button.dataset.sshKey]); terminal.focus(); }));
  const interval = setInterval(() => {
    if (!connected) return;
    const seconds = Math.floor((performance.now() - connectedAt) / 1000);
    $('ssh-duration').textContent = `${Math.floor(seconds / 60)}m ${String(seconds % 60).padStart(2, '0')}s`;
    if (ping && performance.now() - ping.started > 15000) { ping = null; $('ssh-rtt').textContent = 'RTT —'; }
    if (seconds % 5 === 0) probe();
  }, 1000);
  window.addEventListener('pagehide', () => { clearInterval(interval); disconnect(); });
  if (!isSecure) alert('WebSSH requires HTTPS except on localhost. Open your private HTTPS forwarded panel URL before entering credentials.');
  controls();
})();
