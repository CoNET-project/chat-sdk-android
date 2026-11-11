/*
 * Project policy (AGENTS.md, WebSocket rule): no WebSocket client or server in this host.
 * This file runs before the bundled ethers.umd.min.js and openpgp.min.js. It replaces the global
 * WebSocket with a constructor that throws before any socket is created. The bundled libraries are
 * not trimmed (AGENTS.md); their WebSocket paths are blocked at runtime instead.
 * Checked by scripts/ws-negative-probe.mjs (T-9).
 */
(function () {
  'use strict';
  var G = typeof globalThis !== 'undefined' ? globalThis : (typeof self !== 'undefined' ? self : this);
  function WebSocketBlocked() {
    throw new Error('WebSocket is disabled by project policy');
  }
  WebSocketBlocked.CONNECTING = 0;
  WebSocketBlocked.OPEN = 1;
  WebSocketBlocked.CLOSING = 2;
  WebSocketBlocked.CLOSED = 3;
  try {
    Object.defineProperty(G, 'WebSocket', {
      value: WebSocketBlocked,
      writable: false,
      configurable: false,
      enumerable: false,
    });
  } catch (e) {
    G.WebSocket = WebSocketBlocked;
  }
})();
