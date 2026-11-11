// T-9 negative probe: the WebSocket guard must refuse every WebSocket path BEFORE a socket is created.
// Usage: node scripts/ws-negative-probe.mjs   (run from the worktree root)
// A local TCP listener counts connection attempts. A positive control (no guard) must see one,
// so a zero count means the guard blocked the attempt, not that the probe was blind.
import net from 'node:net'
import fs from 'node:fs'
import vm from 'node:vm'

const root = new URL('..', import.meta.url).pathname
const guard = fs.readFileSync(`${root}chat/src/main/assets/ChatCrypto/ws-guard.js`, 'utf8')
const ethersSrc = fs.readFileSync(`${root}chat/src/main/assets/ChatCrypto/ethers.umd.min.js`, 'utf8')

let connections = 0
const server = net.createServer((sock) => { connections++; sock.destroy() })
await new Promise((r) => server.listen(0, '127.0.0.1', r))
const url = `ws://127.0.0.1:${server.address().port}`
const settle = () => new Promise((r) => setTimeout(r, 400))

function sandbox() {
  // Node's own WebSocket stands in for a browser: if the guard fails, a socket would really open.
  // The sandbox global is aliased as window/self/global, as in a browser page (ethers looks for one).
  const ctx = vm.createContext({ console, WebSocket: globalThis.WebSocket, setTimeout, Promise })
  vm.runInContext('globalThis.window = globalThis; globalThis.self = globalThis; globalThis.global = globalThis;', ctx)
  return ctx
}

const results = {}

// Positive control: no guard, a direct construction must open a connection.
{
  const ctx = sandbox()
  vm.runInContext(`globalThis.__c = new WebSocket(${JSON.stringify(url)}); globalThis.__c.onerror = () => {}`, ctx)
  await settle()
  results.controlConnectionsWithoutGuard = connections
  try { vm.runInContext('globalThis.__c && globalThis.__c.close()', ctx) } catch (_) {}
}
connections = 0

// Guarded: direct construction must throw before any connection.
{
  const ctx = sandbox()
  vm.runInContext(guard, ctx)
  vm.runInContext(`globalThis.__r = 'open'; try { new WebSocket(${JSON.stringify(url)}); } catch (e) { globalThis.__r = 'blocked:' + e.message }`, ctx)
  results.directConstructor = vm.runInContext('globalThis.__r', ctx)
  await settle()
  results.directConnections = connections
}
connections = 0

// Guarded: the bundled ethers WebSocketProvider path must also be refused before any connection.
{
  const ctx = sandbox()
  vm.runInContext(guard, ctx)
  vm.runInContext(ethersSrc, ctx)
  vm.runInContext(`globalThis.__e = 'none'; (async () => { try { const p = new ethers.WebSocketProvider(${JSON.stringify(url)}); await p.getBlockNumber(); globalThis.__e = 'connected' } catch (e) { globalThis.__e = 'blocked:' + e.message } })()`, ctx)
  await settle()
  results.ethersWebSocketProvider = vm.runInContext('globalThis.__e', ctx)
  results.ethersConnections = connections
}

server.close()
const ok = results.controlConnectionsWithoutGuard > 0 &&
  String(results.directConstructor).startsWith('blocked:') && results.directConnections === 0 &&
  String(results.ethersWebSocketProvider).startsWith('blocked:') && results.ethersConnections === 0
console.log(JSON.stringify({ ok, ...results }, null, 2))
process.exit(ok ? 0 : 1)
