/* Decrypting service worker. No secrets and no document content live here. */
const VERSION = 1;
const BOOT = '<script>(function(){var K="np.key";function reply(w){var raw=null;try{raw=sessionStorage.getItem(K);}catch(e){}if(!w)return;if(raw)w.postMessage({type:"unlock",raw:raw});else w.postMessage({type:"locked"});}if(!navigator.serviceWorker)return;navigator.serviceWorker.addEventListener("message",function(e){if(e.data&&e.data.type==="need-key")reply(e.source||navigator.serviceWorker.controller);});navigator.serviceWorker.ready.then(function(reg){reply(reg.active);});})();<\/script>';

let key = null;
let manifest = null;
let inflight = null;
const allowed = new Set();
const waiters = new Map();

self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

function b64ToBuf(b64) {
  const s = atob(b64);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes;
}

async function importKey(b64) {
  return crypto.subtle.importKey('raw', b64ToBuf(b64), { name: 'AES-GCM' }, false, ['decrypt']);
}

async function loadManifest(aes) {
  const res = await fetch(new URL('vault.json', self.registration.scope), { cache: 'no-store' });
  if (!res.ok) throw new Error('vault');
  const vault = await res.json();
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBuf(vault.iv) },
    aes,
    b64ToBuf(vault.manifest)
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

async function doUnlock(b64) {
  if (key && manifest) return { key, manifest };
  const aes = await importKey(b64);
  const man = await loadManifest(aes);
  key = aes;
  manifest = man;
  return { key, manifest };
}

function startUnlock(b64) {
  if (!inflight) {
    inflight = doUnlock(b64).catch((err) => {
      inflight = null;
      throw err;
    });
  }
  return inflight;
}

function settle(clientId, err) {
  const waiter = waiters.get(clientId);
  if (!waiter) return;
  waiters.delete(clientId);
  if (err) waiter.reject(err);
  else waiter.resolve();
}

self.addEventListener('message', (event) => {
  const data = event.data || {};
  const clientId = event.source && event.source.id;
  if (data.type === 'claim') {
    self.clients.claim();
    return;
  }
  if (data.type === 'locked' && clientId) {
    settle(clientId, new Error('locked'));
    return;
  }
  if (data.type === 'unlock' && data.raw && clientId) {
    startUnlock(data.raw).then(
      () => {
        allowed.add(clientId);
        settle(clientId, null);
        if (event.source) event.source.postMessage({ type: 'ready' });
      },
      () => {
        settle(clientId, new Error('unlock failed'));
        if (event.source) event.source.postMessage({ type: 'error' });
      }
    );
  }
});

function ensureClient(clientId) {
  if (allowed.has(clientId) && key && manifest) return Promise.resolve();
  const existing = waiters.get(clientId);
  if (existing) return existing.promise;
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  const timer = setTimeout(() => {
    if (waiters.get(clientId) && waiters.get(clientId).promise === promise) {
      waiters.delete(clientId);
      reject(new Error('locked'));
    }
  }, 4000);
  waiters.set(clientId, {
    promise,
    resolve: () => { clearTimeout(timer); resolve(); },
    reject: (err) => { clearTimeout(timer); reject(err); },
  });
  self.clients.get(clientId).then((client) => {
    if (client) client.postMessage({ type: 'need-key' });
  });
  return promise;
}

function relOf(url) {
  const scope = new URL(self.registration.scope);
  if (url.origin !== scope.origin) return null;
  if (!url.pathname.startsWith(scope.pathname)) return null;
  try {
    return decodeURIComponent(url.pathname.slice(scope.pathname.length));
  } catch {
    return null;
  }
}

function isBypass(rel) {
  return rel === ''
    || rel === 'index.html'
    || rel === 'sw.js'
    || rel === 'vault.json'
    || rel === 'robots.txt'
    || rel === 'README.md'
    || rel === '.nojekyll'
    || rel.startsWith('d/')
    || rel.startsWith('scripts/');
}

function maybeContent(rel) {
  return rel === 'calculator.html'
    || rel.startsWith('img/')
    || /\.(html|pdf|png|jpe?g|webp|gif|svg)$/i.test(rel);
}

const mem = new Map();
let memUsed = 0;
const MEM_MAX = 48 * 1024 * 1024;

function remember(id, buf) {
  if (buf.byteLength > MEM_MAX) return;
  while (memUsed + buf.byteLength > MEM_MAX && mem.size) {
    const oldest = mem.keys().next().value;
    memUsed -= mem.get(oldest).byteLength;
    mem.delete(oldest);
  }
  mem.set(id, buf);
  memUsed += buf.byteLength;
}

function decorate(html, via) {
  const tags = '<link rel="icon" href="data:,">' + BOOT;
  let out = html.includes('<head>') ? html.replace('<head>', '<head>' + tags) : tags + html;
  out = out.replace('<html lang="en">', '<html lang="en" data-via="' + via + '">');
  return out;
}

async function plainBuffer(entry) {
  const hit = mem.get(entry.id);
  if (hit) return hit;
  const res = await fetch(new URL('d/' + entry.id + '.bin', self.registration.scope), { cache: 'no-store' });
  if (!res.ok) throw new Error('missing');
  const buf = await res.arrayBuffer();
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: buf.slice(0, 12) },
    key,
    buf.slice(12)
  );
  remember(entry.id, plain);
  return plain;
}

async function serve(rel, clientId) {
  await ensureClient(clientId);
  const entry = manifest.files[rel];
  if (!entry) return new Response('Not found', { status: 404, headers: { 'Cache-Control': 'no-store' } });
  let buf = await plainBuffer(entry);
  let type = entry.type || 'application/octet-stream';
  if (type.startsWith('text/html')) {
    const html = decorate(new TextDecoder().decode(buf), 'sw');
    buf = new TextEncoder().encode(html);
  }
  return new Response(buf, {
    status: 200,
    headers: {
      'Content-Type': type,
      'Cache-Control': 'private, no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const rel = relOf(new URL(event.request.url));
  if (rel == null || isBypass(rel)) return;
  if (!maybeContent(rel)) return;
  const clientId = event.clientId;
  if (!clientId) return;
  event.respondWith(serve(rel, clientId).catch(() =>
    new Response('Locked', { status: 401, headers: { 'Cache-Control': 'no-store' } })
  ));
});

void VERSION;
