/* polpNO · PS4 13.52-only service worker */
const CACHE='polpno-13.52-v14';
const CORE=['./','./index.html','./poops.html','./lapse.html','./chain_13.52.mjs','./lk_boot_1352.mjs','./core.mjs','./mem.mjs','./int64.mjs','./rpc_worker.js','./rpc_worker.mjs','./ps4_13.52.mjs','./payload.bin'];
const PATCH_URL='https://raw.githubusercontent.com/OptiTronOffical/polpNO-use/aec207b31694bb182e032033a1bfab0863c171dd/patches/1352.bin';
self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(CORE)).then(()=>self.skipWaiting())));
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',e=>{
 if(e.request.method!=='GET')return;
 const u=new URL(e.request.url);
 if(u.origin===self.location.origin && u.pathname.endsWith('/patches/1352.bin')){
   e.respondWith(fetch(PATCH_URL,{cache:'no-store'}).catch(()=>caches.match(e.request)));
   return;
 }
 e.respondWith(caches.match(e.request).then(c=>c||fetch(e.request).then(r=>{if(r.ok)caches.open(CACHE).then(x=>x.put(e.request,r.clone()));return r;})));
});
