// 우리집 가계부 — 서비스워커
//
// 배포할 때마다 버전을 올린다. activate에서 옛 캐시를 지우는 유일한 방아쇠라,
// 안 올리면 새 버전을 배포해도 사용자는 계속 옛 화면을 본다.
const CACHE_NAME = 'gagyebu-v5';
const ASSETS = ['/', '/index.html', '/manifest.json', '/icons/icon-192.png', '/icons/icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;

  const url = new URL(e.request.url);

  // ① API는 절대 건드리지 않는다.
  //    예전 서비스워커는 모든 GET을 cache-first로 가로챘다. 그래서 거래를 저장(POST)하면
  //    서버엔 들어가는데, 목록을 다시 부르는 GET이 캐시에 박힌 옛 응답을 받아
  //    "저장 완료"라고 해놓고 화면엔 안 나타났다. 가계부 데이터는 캐시하면 안 된다.
  if (url.origin === location.origin && url.pathname.startsWith('/api/')) return;

  // ② 앱 화면(HTML)은 네트워크 우선.
  //    cache-first로 두면 배포해도 최소 한 번은 옛 버전이 뜨고, 네트워크가 나쁘면 계속 옛 버전이다.
  //    오프라인일 때만 캐시로 떨어진다.
  if (e.request.mode === 'navigate' || url.pathname === '/' || url.pathname.endsWith('.html')) {
    e.respondWith(
      fetch(e.request)
        .then(res => {
          if (res && res.status === 200) {
            const clone = res.clone();
            caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
          }
          return res;
        })
        .catch(() => caches.match(e.request).then(c => c || caches.match('/index.html')))
    );
    return;
  }

  // ③ 그 외 정적 자산(폰트·라이브러리 등)은 캐시 우선 + 뒤에서 갱신.
  e.respondWith(
    caches.match(e.request).then(cached => {
      const fetchPromise = fetch(e.request).then(response => {
        // 교차 출처(CDN) 응답은 status가 0인 opaque라 예전 조건(status===200)에선 캐시되지 않아
        // 오프라인에서 차트·엑셀이 통째로 죽었다. opaque도 함께 저장한다.
        if (response && (response.status === 200 || response.type === 'opaque')) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone)).catch(() => {});
        }
        return response;
      }).catch(() => cached);
      return cached || fetchPromise;
    })
  );
});
