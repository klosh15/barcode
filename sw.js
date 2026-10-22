/* Service worker: guarda la aplicación para que abra sin internet. No guarda datos del inventario. */
const CACHE = 'inventario-v5B-1.0.0';
const ARCHIVOS = ['./', 'index.html', 'app.css', 'app.js', 'manifest.webmanifest',
  'lib/xlsx.full.min.js', 'lib/zxing.min.js', 'icons/icon-192.png', 'icons/icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ARCHIVOS)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const r = e.request;
  if (r.method !== 'GET' || new URL(r.url).origin !== location.origin) return;
  e.respondWith(caches.match(r, { ignoreSearch: true }).then(hit => hit || fetch(r)));
});
