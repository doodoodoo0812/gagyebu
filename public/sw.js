// 우리집 가계부 — 서비스워커
//
// 배포할 때마다 버전을 올린다. activate에서 옛 캐시를 지우는 유일한 방아쇠라,
// 안 올리면 새 버전을 배포해도 사용자는 계속 옛 화면을 본다.
const CACHE_NAME = 'gagyebu-v11';
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

// ===== 웹푸시 =====
// 서버는 '깨우기'만 보낸다(페이로드 없음). 내용은 여기서 직접 받아와 문구를 만든다.
// 앱이 구독할 때 토큰을 캐시에 넣어두므로, 서비스워커도 인증된 요청을 할 수 있다.
const TOKEN_CACHE = 'gagyebu-push-auth';
const TOKEN_URL = 'https://gagyebu.local/push-token';   // 캐시 안에서만 쓰는 가짜 주소(네트워크로 안 나감)

async function readToken() {
  try {
    const c = await caches.open(TOKEN_CACHE);
    const r = await c.match(TOKEN_URL);
    return r ? (await r.text()) : null;
  } catch (e) { return null; }
}

const won = (n) => '₩' + Number(n || 0).toLocaleString('ko-KR');

self.addEventListener('push', e => {
  e.waitUntil((async () => {
    let title = '우리집 가계부';
    let body = '새 거래가 등록됐어요';
    try {
      const token = await readToken();
      if (token) {
        const res = await fetch('/api/push/latest', { headers: { Authorization: 'Bearer ' + token } });
        if (res.ok) {
          const d = await res.json();
          const t = d && d.latest;
          if (t) {
            const who = t.user_name ? `${t.user_name} · ` : '';
            const card = t.card ? ` (${t.card})` : '';
            const verb = t.kind === 'delete' ? '🗑️ 삭제됨' : '✍️ 등록됨';
            title = `${who}${t.name}${card}`;
            body = `${verb} · ${won(t.amount)} · ${t.category}`;
          }
        }
      }
    } catch (err) { /* 못 받아오면 기본 문구로 */ }
    await self.registration.showNotification(title, {
      body,
      icon: '/icons/icon-192.png',
      badge: '/icons/icon-192.png',
      tag: 'gagyebu-tx',        // 연달아 와도 알림이 쌓이지 않고 최신 것으로 바뀐다
      renotify: true,
      data: { url: '/' },
    });
  })());
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil((async () => {
    const all = await clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) {
      if ('focus' in c) return c.focus();   // 이미 열려 있으면 그 창으로
    }
    if (clients.openWindow) return clients.openWindow('/');
  })());
});
