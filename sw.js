const C='xiaomi-v40';
const ASSETS=['./','./index.html','./manifest.webmanifest','./icon-192.png','./icon-512.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(ASSETS)));self.skipWaiting();});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==C).map(k=>caches.delete(k)))));self.clients.claim();});
self.addEventListener('fetch',e=>{
  const u=new URL(e.request.url);
  if(e.request.method!=='GET')return;
  if(u.origin===location.origin){
    // شبکه-اول: همیشه آخرین نسخه اپ؛ فقط در حالت آفلاین از کش استفاده می‌شود
    e.respondWith(
      fetch(e.request).then(res=>{
        const cl=res.clone();caches.open(C).then(c=>c.put(e.request,cl));return res;
      }).catch(()=>caches.match(e.request).then(r=>r||caches.match('./index.html')))
    );
  } else if(u.hostname.includes('jsdelivr')){
    e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request).then(res=>{const cl=res.clone();caches.open(C).then(c=>c.put(e.request,cl));return res;})));
  }
});
