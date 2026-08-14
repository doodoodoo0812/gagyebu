// 우리집 가계부 — Cloudflare Worker (앱 서빙 + D1 데이터 창구)
//
// 왜 Worker를 두는가:
//  이전에는 브라우저가 Supabase를 직접 불렀고, anon key가 화면 소스에 그대로 노출된 채
//  RLS는 "전부 허용"이었다. 즉 주소와 키만 알면 누구나 부부 가계부를 읽고 쓸 수 있었다.
//  Worker를 창구로 두면 키가 서버 밖으로 나가지 않고, 여기서 한 번 걸러진다.
//
// 인증: 부부 공유 비밀번호(APP_PASSWORD) → 서명된 세션 토큰(SESSION_SECRET) 발급.
//       토큰은 stateless(HMAC 서명)라 세션 저장소가 필요 없다.
//       ※ 나중에 카카오를 붙일 때도 이 토큰 발급부(issueToken)만 재사용하면 된다.
//
// 비밀값은 코드가 아니라 Cloudflare secret으로 관리:
//   npx wrangler secret put APP_PASSWORD
//   npx wrangler secret put SESSION_SECRET

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: {
      ...CORS,
      'Content-Type': 'application/json; charset=utf-8',
      // 캐시 금지. 이게 없으면 브라우저가 GET 응답을 재사용해서, 거래를 저장한 직후 목록을 다시 불러도
      // 옛 응답이 돌아온다("저장 완료"라는데 목록에 없는" 현상). 가계부 데이터는 매번 최신이어야 한다.
      'Cache-Control': 'no-store',
    },
  });

const TOKEN_TTL_SEC = 60 * 60 * 24 * 90; // 90일 — 폰에서 매번 로그인하지 않도록

// ───────── 토큰 ─────────
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64url = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// atob는 "한 글자 = 한 바이트"인 문자열을 돌려준다. 그걸 그대로 JSON.parse하면
// '남편' 같은 여러 바이트짜리 글자가 바이트 단위로 쪼개져 깨진다. 반드시 바이트로 되돌린 뒤 UTF-8로 디코딩한다.
function b64urlToText(s) {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '='));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return dec.decode(bytes);
}

async function hmac(data, secret) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

// 타이밍 공격 방지 — 길이가 달라도 조기 반환하지 않는다
function safeEqual(a, b) {
  const x = enc.encode(String(a)), y = enc.encode(String(b));
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

// user는 문자열(옛 방식·이름만) 또는 {id, name}. 개인 계정으로 바뀌며 토큰에 계정 id(u)를 함께 담는다.
// u가 있어야 비밀번호 변경 등 '이 계정' 대상 동작을 할 수 있다(이름은 바뀔 수 있으니 id가 진짜 신원).
async function issueToken(user, secret) {
  const u = (user && typeof user === 'object') ? user : { name: user };
  const payload = b64url(enc.encode(JSON.stringify({
    u: u.id || null,
    n: String(u.name || '').slice(0, 40),
    exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SEC,
  })));
  return `${payload}.${await hmac(payload, secret)}`;
}

// ───────── 비밀번호 해시 (PBKDF2-SHA256) ─────────
// 원문은 저장하지 않는다. 계정마다 무작위 salt로 15만회 파생한 해시만 users에 담고,
// 로그인 때 같은 salt로 다시 파생해 상수시간 비교(safeEqual)한다.
// Cloudflare Workers의 Web Crypto는 PBKDF2 반복을 10만 회로 '상한'을 둔다(초과 시 런타임 오류).
// ★ 로컬 wrangler dev는 이 상한을 안 걸어서 15만도 통과하지만, 운영(workerd)에선 hashPassword가
//   통째로 500으로 죽는다 — 계정 가입·로그인이 조용히 다 실패. 그래서 상한인 10만을 쓴다.
//   (부부 2명·초대코드·레이트리밋 환경이라 10만이면 충분하다.)
const PBKDF2_ITERS = 100000;
const bytesToHex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
function hexToBytes(hex) {
  const s = String(hex || '');
  const out = new Uint8Array(Math.floor(s.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
async function hashPassword(password, saltHex) {
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const km = await crypto.subtle.importKey('raw', enc.encode(String(password)), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' }, km, 256);
  return { salt: bytesToHex(salt), hash: bytesToHex(bits) };
}

// 로그인·가입 공용 레이트리밋. IP별 최근 10분 시도를 세어 임계 초과면 true(차단).
// append-only INSERT 후 카운트라 병렬 요청도 각자 한 건씩 쌓여 throttle을 못 피한다.
// (지연 400ms는 요청 안에서만 걸려 병렬 공격엔 무력하므로, 실제 방어는 이 카운터다.)
async function throttleLogin(env, request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'local';
  const now = Date.now();
  const WINDOW = 10 * 60 * 1000, LIMIT = 10;   // 10분에 10회
  try {
    await env.DB.prepare(`DELETE FROM login_attempts WHERE at < ?1`).bind(now - WINDOW).run();
    await env.DB.prepare(`INSERT INTO login_attempts (ip, at) VALUES (?1, ?2)`).bind(ip, now).run();
    const c = await env.DB.prepare(`SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ?1 AND at > ?2`)
                          .bind(ip, now - WINDOW).first();
    return (c?.n || 0) > LIMIT;
  } catch (e) { return false; /* 카운터 실패가 로그인을 막지는 않게 한다 */ }
}

// 유효하면 payload, 아니면 null
async function verifyToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const payload = token.slice(0, dot), sig = token.slice(dot + 1);
  if (!safeEqual(sig, await hmac(payload, secret))) return null;
  try {
    const p = JSON.parse(b64urlToText(payload));
    if (!p || typeof p.exp !== 'number' || p.exp < Math.floor(Date.now() / 1000)) return null;
    return p;
  } catch { return null; }
}

// ───────── 웹푸시 (앱이 꺼져 있어도 알림) ─────────
// 페이로드 없이 '깨우기'만 보낸다. 내용 암호화(RFC 8291)는 구현·검증이 까다로운데,
// 페이로드 없는 푸시는 VAPID 서명만으로 되고 훨씬 튼튼하다.
// 알림에 쓸 문구는 서비스워커가 깨어나서 /api/push/latest로 직접 받아온다.
function b64urlToBytes(s) {
  const bin = atob(String(s).replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(String(s).length / 4) * 4, '='));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// VAPID JWT(ES256). 푸시 서비스에 "이 서버가 맞다"고 알리는 서명.
async function vapidAuthHeader(env, audience) {
  const jwkRaw = env.VAPID_PRIVATE_JWK;
  const pub = env.VAPID_PUBLIC_KEY;
  if (!jwkRaw || !pub) return null;
  let jwk;
  try { jwk = JSON.parse(jwkRaw); } catch { return null; }

  const key = await crypto.subtle.importKey(
    'jwk', { ...jwk, key_ops: ['sign'], ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
  const header = b64url(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const payload = b64url(enc.encode(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 60 * 60,   // 12시간
    sub: env.VAPID_SUBJECT || 'mailto:admin@example.com',
  })));
  const sigBuf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(`${header}.${payload}`)
  );
  const jwt = `${header}.${payload}.${b64url(sigBuf)}`;
  return { Authorization: `vapid t=${jwt}, k=${pub}` };
}

// 저장된 모든 구독에 푸시를 보낸다. 죽은 구독(404/410)은 그 자리에서 지운다.
// 실패해도 호출한 쪽(거래 저장 등)이 실패하면 안 된다 — 알림은 거들 뿐이다.
// 무엇이 어떻게 됐는지 돌려준다 — 알림이 안 올 때 원인을 화면에서 바로 볼 수 있어야 한다.
// (조용히 실패하면 "왜 안 오지?"를 영영 못 푼다. 실제로 그런 일을 한 번 겪었다.)
async function sendPushToAll(env) {
  const report = { keys: false, sent: 0, results: [] };
  try {
    if (!env.VAPID_PRIVATE_JWK || !env.VAPID_PUBLIC_KEY) {
      report.error = 'VAPID 키가 서버에 없어요';
      return report;
    }
    report.keys = true;
    const subs = (await env.DB.prepare(`SELECT endpoint FROM push_subscriptions`).all()).results ?? [];
    for (const s of subs) {
      const host = (() => { try { return new URL(s.endpoint).host; } catch { return '?'; } })();
      try {
        const u = new URL(s.endpoint);
        const auth = await vapidAuthHeader(env, `${u.protocol}//${u.host}`);
        if (!auth) { report.results.push({ host, error: 'VAPID 서명 실패' }); continue; }
        const res = await fetch(s.endpoint, {
          method: 'POST',
          headers: { ...auth, TTL: '86400', 'Content-Length': '0' },
        });
        // 401/403 = VAPID가 거부됨(키·서명 문제). 404/410 = 죽은 구독. 201/200 = 접수됨.
        let detail = '';
        if (!res.ok) { try { detail = (await res.text()).slice(0, 160); } catch (e) {} }
        report.results.push({ host, status: res.status, detail });
        if (res.ok) report.sent++;
        // 애플은 죽은 구독에 400 BadWebPushToken을 준다(404/410이 아니다). 이것도 영구 무효라 지운다.
        const appleDead = res.status === 400 && /BadWebPushToken|BadDeviceToken/i.test(detail);
        if (res.status === 404 || res.status === 410 || appleDead) {
          await env.DB.prepare(`DELETE FROM push_subscriptions WHERE endpoint = ?1`).bind(s.endpoint).run();
          report.results[report.results.length - 1].removed = true;
        }
      } catch (e) {
        report.results.push({ host, error: String(e?.message || e).slice(0, 160) });
      }
    }
  } catch (e) {
    report.error = String(e?.message || e).slice(0, 160);
  }
  return report;
}

// 마지막 동작(등록/삭제)을 app_settings에 남기고 모두에게 푸시를 보낸다.
// 서비스워커는 /api/push/latest 로 이 값을 읽어 알림 문구를 만든다(삭제도 올바른 문구가 나오게).
async function recordAndPush(env, ev) {
  try {
    await setSetting(env, 'push_latest', JSON.stringify({
      kind: ev.kind || 'add',
      name: String(ev.name ?? '').slice(0, 100),
      amount: Number(ev.amount) || 0,
      category: String(ev.category ?? '').slice(0, 40),
      user_name: String(ev.user_name ?? '').slice(0, 40),
      card: ev.card ? String(ev.card).slice(0, 20) : '',
    }));
  } catch (e) { /* 기록 실패해도 푸시는 보낸다 */ }
  return await sendPushToAll(env);
}

// ───────── 입력 검증 ─────────
// DB에도 CHECK 제약이 있지만(schema.sql), 여기서 먼저 걸러야 사용자가 한글 안내를 본다.
// 형식만 보면 부족하다 — '2026-04-31'은 모양은 멀쩡하지만 달력에 없는 날이고,
// 그런 날짜가 통과하면 DB 제약에 걸려 원시 SQL 오류가 500으로 새어 나간다.
const isDate = (s) => {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  // 없는 날짜는 JS가 다음 달로 넘겨버리므로(4/31 → 5/1) 되돌려 비교해 잡아낸다
  return !isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
};
const isMonth = (s) => typeof s === 'string' && /^\d{4}-(0[1-9]|1[0-2])$/.test(s);

function cleanTx(b) {
  const amount = Number(b?.amount);
  if (!isDate(b?.date)) return { err: '날짜 형식이 올바르지 않아요' };
  if (b.type !== 'income' && b.type !== 'expense') return { err: '수입/지출 구분이 올바르지 않아요' };
  if (!b.category || String(b.category).length > 40) return { err: '카테고리를 확인해 주세요' };
  if (!b.name || String(b.name).length > 100) return { err: '항목명을 확인해 주세요' };
  if (!Number.isInteger(amount) || amount <= 0) return { err: '금액은 1원 이상의 정수여야 해요' };
  return {
    tx: {
      date: b.date,
      type: b.type,
      category: String(b.category),
      name: String(b.name),
      amount,
      memo: String(b.memo ?? '').slice(0, 500),
      photo_url: b.photo_url ?? null,
      is_recurring: b.is_recurring ? 1 : 0,
      user_name: String(b.user_name ?? '').slice(0, 40),
      card: b.card ? String(b.card).slice(0, 20) : null,   // 카드사(선택). 일시불에도 기록 가능.
      // 수정 시 photo_url 키 자체가 없으면 기존 사진을 건드리지 않는다.
      // 목록 응답에 photo_url이 빠져 있어서 앱이 되돌려줄 값을 갖고 있지 않기 때문 —
      // 이걸 구분하지 않으면 거래를 수정할 때마다 첨부한 영수증이 지워진다.
      _setPhoto: Object.prototype.hasOwnProperty.call(b, 'photo_url') ? 1 : 0,
    },
  };
}

// 목록에는 photo_url을 절대 넣지 않는다. 영수증 사진은 base64 데이터 URL이라 한 장이 수백KB~수MB인데,
// 6개월치를 그대로 실어 보내면 응답이 수십 MB가 되어 Worker 메모리와 응답 한도를 넘긴다.
// 목록엔 "사진이 있냐"만 담고(has_photo), 실제 이미지는 볼 때 /api/tx/:id/photo 로 따로 가져온다.
const TX_COLS = `id, created_at, date, type, category, name, amount, memo, is_recurring, user_name,
                 card, installment_id, installment_seq, installment_months,
                 (photo_url IS NOT NULL) AS has_photo`;

// 날짜에 add개월을 더하되 그 달에 없는 날은 말일로 맞춘다(1/31 +1개월 → 2/28). 할부 회차 날짜 계산용.
// UTC로 계산해 타임존 영향 없음.
function addMonthsClamp(dateStr, add) {
  const [y, m, d] = dateStr.split('-').map(Number);
  const total = (m - 1) + add;
  const ny = y + Math.floor(total / 12);
  const nm = ((total % 12) + 12) % 12;                       // 0-based month
  const lastDay = new Date(Date.UTC(ny, nm + 1, 0)).getUTCDate();
  const nd = Math.min(d, lastDay);
  return `${ny}-${String(nm + 1).padStart(2, '0')}-${String(nd).padStart(2, '0')}`;
}

// ───────── 설정 저장소 (app_settings) ─────────
async function getSetting(env, key) {
  const r = await env.DB.prepare(`SELECT value FROM app_settings WHERE key = ?1`).bind(key).first();
  return r?.value ?? null;
}
async function setSetting(env, key, value) {
  await env.DB.prepare(
    `INSERT INTO app_settings (key, value, updated_at) VALUES (?1, ?2, datetime('now'))
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`
  ).bind(key, value).run();
}
function safeParse(s) { try { return JSON.parse(s); } catch { return null; } }

// 카테고리 편집(숨김/이름/이모지/순서) 오버라이드를 안전한 모양으로 정리한다.
// 내장 카테고리는 클라이언트 상수라 못 바꾸므로 '덮어쓰기'만 저장한다. name(대상 key)은 저장 안 하고
// overrides의 '키'로만 쓴다 — 그 key(원래 이름)가 거래에 저장된 식별자라 절대 바뀌면 안 된다.
function cleanCategoryOverrides(obj) {
  const out = {};
  for (const type of ['expense', 'income']) {
    const src = (obj && typeof obj === 'object' && obj[type]) || {};
    const srcOv = (src.overrides && typeof src.overrides === 'object') ? src.overrides : {};
    const overrides = {};
    let count = 0;
    for (const k of Object.keys(srcOv)) {
      if (count++ >= 80) break;                                   // 방어적 상한
      const key = String(k).slice(0, 40);
      const v = srcOv[k] || {};
      const o = {};
      if (v.hidden) o.hidden = 1;
      if (v.label != null && String(v.label).trim()) o.label = String(v.label).trim().slice(0, 20);
      if (v.emoji != null && String(v.emoji).trim()) o.emoji = String(v.emoji).trim().slice(0, 8);
      if (Object.keys(o).length) overrides[key] = o;
    }
    const order = Array.isArray(src.order) ? src.order.slice(0, 80).map(x => String(x).slice(0, 40)) : [];
    out[type] = { overrides, order };
  }
  return out;
}

// 앱 설정에서 넣은 키가 우선. 없으면 wrangler secret(GEMINI_API_KEY)을 쓴다.
async function geminiKey(env) {
  return (await getSetting(env, 'gemini_key')) || env.GEMINI_API_KEY || null;
}

// ───────── Gemini 모델 자동 감지 ─────────
// 모델명을 코드에 박아두면 구글이 그 모델을 폐기하는 순간 기능이 통째로 죽는다.
// 실제로 gemini-1.5-flash가 폐기돼서 영수증 인식이 아무 설명 없이 안 됐다.
// 그래서 쓸 수 있는 모델을 물어보고 고른다.
function pickGeminiModel(models, exclude) {
  const id = m => String(m.name || '').replace(/^models\//, '');
  const skip = exclude instanceof Set ? exclude : new Set();
  const usable = (models || []).filter(m =>
    (m.supportedGenerationMethods || []).includes('generateContent') && /^gemini-/.test(id(m)) && !skip.has(id(m))
  );
  const score = (m) => {
    const n = id(m);
    let s = 0;
    // 영수증 사진 한 장 읽고 짧은 JSON을 뱉는 일이라 flash가 맞다(빠르고 싸다).
    if (/flash/.test(n)) s += 100;
    if (/\blite\b|-lite/.test(n)) s -= 20;                  // lite는 인식 품질이 떨어질 수 있어 후순위
    if (/preview|exp|experimental|thinking/.test(n)) s -= 60; // 미리보기는 예고 없이 사라진다
    if (/-\d{3,}$/.test(n)) s -= 5;                          // -001 같은 스냅샷보다 별칭(자동 최신)을 선호
    const v = parseFloat((n.match(/gemini-(\d+(?:\.\d+)?)/) || [])[1] || 0);
    s += v * 10;                                             // 버전이 높을수록
    return s;
  };
  usable.sort((a, b) => score(b) - score(a));
  return usable.length ? { model: id(usable[0]), candidates: usable.slice(0, 8).map(id) } : null;
}

// 키를 구글에 넘기는 방법은 세 가지고, 계정·키 종류에 따라 통하는 게 다르다.
// 어느 게 맞는지 추측하지 말고 순서대로 다 시도한 뒤, 통한 방식을 기억해 다음부터 한 번에 간다.
// 두 방식을 '동시에' 쓰면 'Multiple authentication credentials received'가 나므로 반드시 하나씩 쓴다.
//
// 실측(2026-08): 가짜 키로 채널만 확인한 결과
//   AIza… + ?key=          → 400 API_KEY_INVALID          (API 키로 인식됨)
//   AIza… + x-goog-api-key → 400 API_KEY_INVALID          (헤더 채널도 API 키에 유효)
//   AQ.…  + 세 방식 모두    → 401 ACCESS_TOKEN_TYPE_UNSUPPORTED / API_KEY_SERVICE_BLOCKED
// 즉 'AQ.'로 시작하는 값은 이 API가 애초에 API 키로 받아주지 않는다(재시도로 해결되지 않음).
const GEMINI_AUTH_MODES = ['query', 'header', 'bearer'];

function geminiRequestOnce(base, key, mode, init) {
  if (mode === 'query') {
    const sep = base.includes('?') ? '&' : '?';
    return fetch(base + sep + 'key=' + encodeURIComponent(key), init);
  }
  const auth = mode === 'header' ? { 'x-goog-api-key': key } : { 'Authorization': 'Bearer ' + key };
  return fetch(base, { ...init, headers: { ...(init.headers || {}), ...auth } });
}

async function geminiFetch(pathAndQuery, key, init = {}, env = null) {
  const base = 'https://generativelanguage.googleapis.com/v1beta/' + pathAndQuery;
  // 지난번에 통한 방식이 있으면 그것부터 — 매번 3번씩 두드리지 않도록.
  const saved = env ? await getSetting(env, 'gemini_auth_mode') : null;
  const order = (saved && GEMINI_AUTH_MODES.includes(saved))
    ? [saved, ...GEMINI_AUTH_MODES.filter(m => m !== saved)]
    : GEMINI_AUTH_MODES;

  let last = null;
  for (const mode of order) {
    const res = await geminiRequestOnce(base, key, mode, init);
    // 401/403은 '이 방식으로는 인증이 안 된다'는 뜻이라 다음 방식으로 넘어간다.
    // 그 외(200, 400 API_KEY_INVALID, 404 …)는 인증 채널은 통했다는 뜻이므로 그대로 돌려준다.
    if (res.status !== 401 && res.status !== 403) {
      // 방식을 '기억'하는 건 실제로 성공했을 때만. 400(키 자체가 무효) 같은 실패까지 기억하면
      // 저장도 안 된 키의 방식이 설정에 남는다.
      if (env && res.ok && mode !== saved) await setSetting(env, 'gemini_auth_mode', mode);
      return res;
    }
    last = res;
  }
  return last;   // 셋 다 인증 거부
}

// 구글이 돌려준 오류를 사용자 안내로 바꾼다.
// 안내는 '사용자가 다음에 뭘 해야 하는지'가 분명해야 한다. 예전 문구는 'AQ.' 키에 대해
// "잠시 후 다시 시도"라고 해서, 영영 통하지 않을 값을 계속 다시 넣게 만들었다(실측으로 확인).
function friendlyGeminiError(error, key) {
  const msg = String(error?.message || error || '');
  const k = String(key || '');

  // 'AQ.'로 시작하는 값은 세 가지 인증 방식 모두에서 "API 키가 아니다"로 거부된다.
  // 기다린다고 통하지 않으므로, 올바른 키를 받는 방법을 알려준다.
  if (k.startsWith('AQ.')) {
    return 'AQ.로 시작하는 이 값은 Gemini API 키가 아니에요(구글이 API 키로 받지 않습니다). ' +
           'AI Studio(aistudio.google.com/apikey)에서 [API 키 만들기]로 AIza로 시작하는 키를 새로 만들어 넣어 주세요. ' +
           'AQ.만 나오면, 키를 만들 때 기존 Google Cloud 프로젝트를 선택해 만들면 AIza 키가 나옵니다.';
  }
  if (/API[_ ]?KEY[_ ]?INVALID|API key not valid/i.test(msg)) {
    return '키가 올바르지 않아요. 앞뒤 공백이나 빠진 글자가 없는지 확인해 주세요. (AI Studio에서 다시 복사하면 확실해요.)';
  }
  if (/SERVICE_DISABLED|has not been used in project|is disabled/i.test(msg)) {
    return '이 키의 프로젝트에서 Gemini API가 꺼져 있어요. Google Cloud Console에서 "Generative Language API"를 켜고 몇 분 뒤 다시 시도해 주세요.';
  }
  if (/ACCESS_TOKEN_TYPE_UNSUPPORTED|PERMISSION_DENIED|invalid authentication|API_KEY_SERVICE_BLOCKED/i.test(msg)) {
    return '이 값으로는 구글 인증이 되지 않아요. AI Studio에서 만든 AIza로 시작하는 API 키인지 확인해 주세요. ' +
           '(구글 원문: ' + msg.slice(0, 120) + ')';
  }
  return msg || '키를 확인해 주세요';
}

async function listGeminiModels(key, env = null) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    const res = await geminiFetch('models?pageSize=200', key, { signal: ctrl.signal }, env);
    const data = await res.json();
    if (data?.error) return { err: friendlyGeminiError(data.error, key) };
    return { models: data?.models || [] };
  } catch (e) {
    return { err: e?.name === 'AbortError' ? '구글 응답이 너무 늦어요' : '연결 실패: ' + e.message };
  } finally {
    clearTimeout(timer);
  }
}

// 저장된 모델을 쓰되, 없거나 폐기됐으면 다시 찾아서 저장한다.
async function currentGeminiModel(env, key, force = false) {
  if (!force) {
    const saved = await getSetting(env, 'gemini_model');
    if (saved) return saved;
  }
  const { models, err } = await listGeminiModels(key, env);
  if (err) return null;
  const picked = pickGeminiModel(models);
  if (!picked) return null;
  await setSetting(env, 'gemini_model', picked.model);
  return picked.model;
}

// Gemini 호출 + 모델이 사라졌으면(404/NOT_FOUND) 한 번 자동 재탐지 후 재시도.
async function callGemini(env, key, body) {
  let model = await currentGeminiModel(env, key);
  if (!model) return { err: 'AI 설정을 확인해 주세요 (사용 가능한 모델을 찾지 못했어요)' };

  const once = async (m) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 25000);
    try {
      const res = await geminiFetch(`models/${encodeURIComponent(m)}:generateContent`, key, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: ctrl.signal, body: JSON.stringify(body),
      }, env);
      return { status: res.status, data: await res.json() };
    } catch (e) {
      return { err: e?.name === 'AbortError' ? 'AI 응답이 너무 늦어요. 직접 입력해 주세요' : 'AI 호출 실패: ' + e.message };
    } finally {
      clearTimeout(timer);
    }
  };

  const dead = (rr) => rr.status === 404 || /not found|is not supported|deprecated/i.test(rr.data?.error?.message || '');

  let r = await once(model);
  if (r.err) return r;

  // 모델이 폐기·삭제된 경우. gemini-1.5-flash 때 앱이 죽은 그 상황이다. 스스로 회복한다.
  // 실패한 모델을 '제외'하고 다음 후보를 고른다 — 안 그러면 ListModels에 아직 남아있는 죽은 모델을
  // 또 골라 무한히 같은 실패를 반복한다(예전 버그).
  if (dead(r)) {
    const excluded = new Set([model]);
    const { models } = await listGeminiModels(key, env);
    for (let i = 0; i < 3; i++) {   // 죽은 모델을 차례로 빼며 최대 3개 후보까지 시도
      const picked = pickGeminiModel(models, excluded);
      if (!picked) break;
      console.warn('모델', model, '실패 → 다음 후보', picked.model);
      await setSetting(env, 'gemini_model', picked.model);
      model = picked.model;
      r = await once(model);
      if (r.err) return r;
      if (!dead(r)) break;
      excluded.add(model);
    }
  }
  if (r.data?.error) {
    console.warn('Gemini 오류:', JSON.stringify(r.data.error).slice(0, 300));
    const msg = String(r.data.error.message || '');
    if (/ACCESS_TOKEN_TYPE_UNSUPPORTED|API[_ ]?KEY[_ ]?INVALID|API key not valid|PERMISSION_DENIED/i.test(msg))
      return { err: friendlyGeminiError(r.data.error, key) };
    return { err: 'AI 인식에 실패했어요. 직접 입력해 주세요' };
  }
  return { text: r.data?.candidates?.[0]?.content?.parts?.[0]?.text || '' };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    // API가 아니면 정적 자산(앱)
    if (!path.startsWith('/api/')) {
      if (env.ASSETS) return env.ASSETS.fetch(request);
      return new Response('Not found', { status: 404 });
    }

    if (!env.APP_PASSWORD || !env.SESSION_SECRET) {
      return json({ error: '서버 설정이 끝나지 않았어요 (APP_PASSWORD / SESSION_SECRET 미설정)' }, 500);
    }
    if (!env.DB) return json({ error: '데이터베이스가 연결되지 않았어요' }, 500);

    try {
      // ── 로그인 ──
      // 로그인 화면이 '로그인'과 '계정 만들기' 중 무엇을 먼저 보여줄지 정하는 데 쓴다(공개).
      // 계정이 하나도 없으면 앱이 '계정 만들기'를 먼저 띄운다.
      if (path === '/api/auth/status' && request.method === 'GET') {
        let hasUsers = false;
        try {
          const c = await env.DB.prepare(`SELECT COUNT(*) AS n FROM users`).first();
          hasUsers = (c?.n || 0) > 0;
        } catch (e) { /* users 테이블이 아직 없으면 조용히 false */ }
        return json({ hasUsers });
      }

      // 계정 만들기 — 가입 코드(= 예전 공유 비밀번호 APP_PASSWORD)를 아는 사람만 만들 수 있다.
      // 만든 뒤부터는 자기 이름+비밀번호로 로그인하고, 비밀번호도 본인이 바꾼다. 데이터는 그대로 공유.
      if (path === '/api/signup' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        if (await throttleLogin(env, request)) return json({ error: '시도가 너무 많아요. 잠시 후 다시 시도해 주세요' }, 429);
        await new Promise((r) => setTimeout(r, 400));
        if (!safeEqual(b?.code ?? '', env.APP_PASSWORD)) return json({ error: '가입 코드가 맞지 않아요' }, 401);
        const name = String(b?.name ?? '').trim().slice(0, 40);
        const password = String(b?.password ?? '');
        if (name.length < 1) return json({ error: '이름을 입력해 주세요' }, 400);
        if (!/^\d{4,}$/.test(password)) return json({ error: '비밀번호는 숫자로만, 4자리 이상으로 정해 주세요' }, 400);
        const dup = await env.DB.prepare(`SELECT id FROM users WHERE name = ?1`).bind(name).first();
        if (dup) return json({ error: '이미 있는 이름이에요. 로그인해 주세요' }, 409);
        const { salt, hash } = await hashPassword(password);
        const id = crypto.randomUUID();
        await env.DB.prepare(`INSERT INTO users (id, name, salt, hash) VALUES (?1, ?2, ?3, ?4)`).bind(id, name, salt, hash).run();
        return json({ token: await issueToken({ id, name }, env.SESSION_SECRET), name });
      }

      // 로그인 — 이름 + 자기 비밀번호.
      if (path === '/api/login' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        if (await throttleLogin(env, request)) return json({ error: '로그인 시도가 너무 많아요. 잠시 후 다시 시도해 주세요' }, 429);
        await new Promise((r) => setTimeout(r, 400));  // 무차별 대입 속도를 떨어뜨린다(보조 수단)
        const name = String(b?.name ?? '').trim().slice(0, 40);
        const password = String(b?.password ?? '');
        const u = name ? await env.DB.prepare(`SELECT id, name, salt, hash FROM users WHERE name = ?1`).bind(name).first() : null;
        if (u) {
          const { hash } = await hashPassword(password, u.salt);
          if (safeEqual(hash, u.hash)) {
            return json({ token: await issueToken({ id: u.id, name: u.name }, env.SESSION_SECRET), name: u.name });
          }
        } else {
          // 이름이 없어도 해시를 한 번 계산해 응답 시간을 계정 있을 때와 맞춘다.
          // 안 그러면 '이 이름의 계정이 있나'가 응답 속도(PBKDF2 유무)로 새어 나간다(타이밍 사이드채널).
          await hashPassword(password, '0'.repeat(32));
          // 하위호환 부트스트랩: 계정이 하나도 없던 시절엔 예전 공유 비밀번호로도 들어올 수 있다.
          // 첫 계정이 만들어지는 순간부터는 막혀, 나머지도 각자 계정을 만들게 된다.
          let anyUser = 0;
          try { anyUser = (await env.DB.prepare(`SELECT COUNT(*) AS n FROM users`).first())?.n || 0; } catch (e) {}
          if (anyUser === 0 && safeEqual(password, env.APP_PASSWORD)) {
            return json({ token: await issueToken({ id: null, name }, env.SESSION_SECRET), name });
          }
        }
        // 이름이 없는지 비번이 틀린지 구분해 알려주지 않는다(이름 추측을 돕지 않으려고).
        return json({ error: '이름 또는 비밀번호가 맞지 않아요' }, 401);
      }

      // 비밀번호 재설정 — 현재 비번을 몰라도, 가입 코드(공유 비밀번호)를 아는 사람이 이름으로 새 비번을 정한다.
      // 부부가 코드를 공유하는 구조라 코드를 아는 사람은 어느 계정이든 재설정 가능(집 안 마스터키 성격).
      // 성공하면 바로 그 계정으로 로그인시킨다.
      if (path === '/api/reset-password' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        if (await throttleLogin(env, request)) return json({ error: '시도가 너무 많아요. 잠시 후 다시 시도해 주세요' }, 429);
        await new Promise((r) => setTimeout(r, 400));
        if (!safeEqual(b?.code ?? '', env.APP_PASSWORD)) return json({ error: '가입 코드가 맞지 않아요' }, 401);
        const name = String(b?.name ?? '').trim().slice(0, 40);
        const password = String(b?.password ?? '');
        if (!/^\d{4,}$/.test(password)) return json({ error: '새 비밀번호는 숫자로만, 4자리 이상으로 정해 주세요' }, 400);
        const u = name ? await env.DB.prepare(`SELECT id, name FROM users WHERE name = ?1`).bind(name).first() : null;
        // 여기선 코드로 이미 본인임을 증명했으므로 '없는 이름'을 알려줘도 된다(도움이 됨).
        if (!u) return json({ error: '그 이름의 계정이 없어요. 이름을 확인해 주세요' }, 404);
        const { salt, hash } = await hashPassword(password);
        await env.DB.prepare(`UPDATE users SET salt = ?1, hash = ?2 WHERE id = ?3`).bind(salt, hash, u.id).run();
        return json({ token: await issueToken({ id: u.id, name: u.name }, env.SESSION_SECRET), name: u.name });
      }

      // ── 이하 전부 인증 필요 ──
      const auth = request.headers.get('Authorization') || '';
      const session = await verifyToken(auth.replace(/^Bearer\s+/i, ''), env.SESSION_SECRET);
      if (!session) return json({ error: '로그인이 필요해요' }, 401);

      if (path === '/api/me' && request.method === 'GET') {
        return json({ name: session.n, id: session.u || null });
      }

      // 비밀번호 변경 — 본인 계정만(토큰의 u가 곧 신원). 현재 비밀번호 확인 후 교체.
      if (path === '/api/password' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        if (!session.u) {
          return json({ error: '이 로그인은 옛 방식이라 비밀번호를 바꿀 수 없어요. 로그아웃 후 "계정 만들기"로 내 계정을 만들어 주세요' }, 400);
        }
        const current = String(b?.current ?? '');
        const next = String(b?.next ?? '');
        if (!/^\d{4,}$/.test(next)) return json({ error: '새 비밀번호는 숫자로만, 4자리 이상으로 정해 주세요' }, 400);
        const u = await env.DB.prepare(`SELECT salt, hash FROM users WHERE id = ?1`).bind(session.u).first();
        if (!u) return json({ error: '계정을 찾을 수 없어요. 다시 로그인해 주세요' }, 404);
        const cur = await hashPassword(current, u.salt);
        if (!safeEqual(cur.hash, u.hash)) return json({ error: '현재 비밀번호가 맞지 않아요' }, 401);
        const nu = await hashPassword(next);
        await env.DB.prepare(`UPDATE users SET salt = ?1, hash = ?2 WHERE id = ?3`).bind(nu.salt, nu.hash, session.u).run();
        return json({ ok: true });
      }

      // ── 한 달치 화면에 필요한 것을 한 번에 ──
      //  from~to는 통계의 6개월 추이 때문에 6개월 창으로 부른다.
      //  상한은 '다음 달 1일 미만'. 예전 Supabase 코드가 '월-31'을 상한으로 삼는 바람에
      //  30일 달과 2월에 쿼리가 통째로 실패해 그 달이 빈 화면이 됐었다.
      if (path === '/api/data' && request.method === 'GET') {
        const from = url.searchParams.get('from');
        const to = url.searchParams.get('to');
        const month = url.searchParams.get('month');
        if (!isDate(from) || !isDate(to) || !isMonth(month)) return json({ error: '조회 기간이 올바르지 않아요' }, 400);

        // 휴지통 자동 비우기 — 삭제한 지 30일 지난 건 여기서 완전삭제(사진까지). 데이터 로드마다 한 번씩 청소.
        // 실패해도 로딩을 막지 않는다(정리는 다음 기회에 다시 시도).
        try {
          await env.DB.prepare(`DELETE FROM transactions WHERE deleted_at IS NOT NULL AND deleted_at < datetime('now','-30 days')`).run();
        } catch (e) { console.warn('휴지통 자동정리 실패:', String(e?.message || e)); }

        const tx = await env.DB.prepare(
          `SELECT ${TX_COLS} FROM transactions WHERE date >= ?1 AND date < ?2 AND deleted_at IS NULL ORDER BY date DESC`
        ).bind(from, to).all();

        const bud = await env.DB.prepare(
          `SELECT id, month, category, amount FROM budgets WHERE month = ?1`
        ).bind(month).all();

        return json({ transactions: tx.results ?? [], budgets: bud.results ?? [] });
      }

      // ── 전체 거래 (엑셀 '전체 내보내기' 전용) ──
      //  화면용 배열은 6개월치뿐이라, '전체'를 자처하는 파일을 그걸로 만들면 안 된다.
      if (path === '/api/tx/all' && request.method === 'GET') {
        const r = await env.DB.prepare(`SELECT ${TX_COLS} FROM transactions WHERE deleted_at IS NULL ORDER BY date DESC`).all();
        return json({ transactions: r.results ?? [] });
      }

      // ── 전체 기간 검색 ──
      //  화면 배열은 최근 1년치뿐이라 그보다 오래된 건 로컬 검색으로 안 잡힌다. DB 전체를 검색한다.
      if (path === '/api/search' && request.method === 'GET') {
        const q = (url.searchParams.get('q') || '').trim();
        if (!q) return json({ transactions: [], limited: false });
        const like = '%' + q.replace(/[\\%_]/g, m => '\\' + m) + '%';   // LIKE 와일드카드 이스케이프
        const digits = q.replace(/[^0-9]/g, '');
        const LIMIT = 300;
        const r = await env.DB.prepare(
          `SELECT ${TX_COLS} FROM transactions
           WHERE deleted_at IS NULL AND (
             name LIKE ?1 ESCAPE '\\' OR memo LIKE ?1 ESCAPE '\\'
             OR category LIKE ?1 ESCAPE '\\' OR user_name LIKE ?1 ESCAPE '\\'
             OR (length(?2) >= 2 AND CAST(amount AS TEXT) LIKE '%' || ?2 || '%')
           )
           ORDER BY date DESC LIMIT ${LIMIT}`
        ).bind(like, digits).all();
        const rows = r.results ?? [];
        return json({ transactions: rows, limited: rows.length >= LIMIT });
      }

      // ── 거래 추가 ──
      if (path === '/api/tx' && request.method === 'POST') {
        const { tx, err } = cleanTx(await request.json().catch(() => ({})));
        if (err) return json({ error: err }, 400);
        const id = crypto.randomUUID();

        // 정기 지출은 UNIQUE 부분 인덱스(date,name)로 중복이 막혀 있다.
        // 부부가 같은 날 동시에 앱을 열면 양쪽 다 "아직 없음"으로 읽고 둘 다 넣으려 하므로,
        // 충돌을 오류로 올리지 않고 무시한 뒤 이미 있는 행을 돌려준다.
        if (tx.is_recurring) {
          await env.DB.prepare(
            `INSERT OR IGNORE INTO transactions (id,date,type,category,name,amount,memo,photo_url,is_recurring,user_name)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1,?9)`
          ).bind(id, tx.date, tx.type, tx.category, tx.name, tx.amount, tx.memo, tx.photo_url, tx.user_name).run();
          const row = await env.DB.prepare(
            `SELECT ${TX_COLS} FROM transactions WHERE date = ?1 AND name = ?2 AND is_recurring = 1 AND deleted_at IS NULL`
          ).bind(tx.date, tx.name).first();
          return json({ tx: row });
        }

        await env.DB.prepare(
          `INSERT INTO transactions (id,date,type,category,name,amount,memo,photo_url,is_recurring,user_name,card)
           VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0,?9,?10)`
        ).bind(id, tx.date, tx.type, tx.category, tx.name, tx.amount, tx.memo, tx.photo_url, tx.user_name, tx.card).run();
        const row = await env.DB.prepare(`SELECT ${TX_COLS} FROM transactions WHERE id = ?1`).bind(id).first();
        // 등록되면 두 사람 모두에게 알림. 실패해도 저장은 이미 끝났으므로 응답을 막지 않는다.
        await recordAndPush(env, { kind: 'add', name: tx.name, amount: tx.amount, category: tx.category, user_name: tx.user_name, card: tx.card });
        return json({ tx: row });
      }

      // ── 이월 카드값(앱 시작 전에 쌓인 카드값) 일괄 등록 ──
      //  결제 예정일에 '카드대금' 지출로 넣는다. card 컬럼은 비운다 — 카드로 넣으면 결제월 재계산(billingMonthOf)에
      //  휘말려 다른 달로 밀린다. 카드사 이름은 항목명에 담아 어느 카드인지 보이게 한다. 대량이라 푸시는 안 보낸다.
      if (path === '/api/carryover' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        const items = Array.isArray(b?.items) ? b.items.slice(0, 100) : [];
        const user_name = String(session?.n ?? '').slice(0, 40);   // 로그인한 사람으로 귀속
        const stmts = [];
        for (const it of items) {
          const amount = Math.floor(Number(it?.amount));
          const card = String(it?.card ?? '').trim().slice(0, 20);
          if (!isDate(it?.date) || !card) continue;
          if (!Number.isInteger(amount) || amount <= 0 || amount >= 100000000000) continue;
          stmts.push(env.DB.prepare(
            `INSERT INTO transactions (id,date,type,category,name,amount,memo,photo_url,is_recurring,user_name,card)
             VALUES (?1,?2,'expense','카드대금',?3,?4,'이월 카드값',NULL,0,?5,NULL)`
          ).bind(crypto.randomUUID(), it.date, `${card} 카드대금`, amount, user_name));
        }
        if (stmts.length) await env.DB.batch(stmts);
        return json({ ok: true, added: stmts.length });
      }

      // ── 무이자 할부 등록 ──
      //  N개월치 거래를 각 달에 미리 만들어 같은 installment_id로 묶는다. 그러면 매달 그 달 목록/통계/예산에
      //  자동으로 뜨고(다음 달에도 계속 표시), N개월 지나면 더 안 생긴다. 취소는 그룹을 한 번에.
      //  batch라 N건이 모두 커밋되거나 모두 안 된다(중간에 몇 건만 남는 일 없음).
      if (path === '/api/installment' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        const total = Number(b?.amount), months = Number(b?.months);
        if (!isDate(b?.date)) return json({ error: '날짜 형식이 올바르지 않아요' }, 400);
        if (!b?.category || String(b.category).length > 40) return json({ error: '카테고리를 확인해 주세요' }, 400);
        if (!b?.name || String(b.name).length > 100) return json({ error: '항목명을 확인해 주세요' }, 400);
        if (!Number.isInteger(months) || months < 2 || months > 24) return json({ error: '할부 개월수는 2~24 사이여야 해요' }, 400);
        if (!Number.isInteger(total) || total < months) return json({ error: '할부 총액이 개월수보다 커야 해요(월 1원 이상)' }, 400);
        if (total >= 100000000000) return json({ error: '금액이 너무 커요' }, 400);
        const card = b.card ? String(b.card).slice(0, 20) : null;
        const memo = String(b.memo ?? '').slice(0, 500);
        const user_name = String(b.user_name ?? '').slice(0, 40);
        const base = Math.floor(total / months);
        const rem = total - base * months;           // 첫 회차가 나머지를 흡수 → 합계가 정확히 total
        const groupId = crypto.randomUUID();
        const stmts = [];
        for (let k = 1; k <= months; k++) {
          const amt = base + (k === 1 ? rem : 0);
          const date = addMonthsClamp(b.date, k - 1);
          stmts.push(env.DB.prepare(
            `INSERT INTO transactions (id,date,type,category,name,amount,memo,photo_url,is_recurring,user_name,card,installment_id,installment_seq,installment_months)
             VALUES (?1,?2,'expense',?3,?4,?5,?6,NULL,0,?7,?8,?9,?10,?11)`
          ).bind(crypto.randomUUID(), date, String(b.category), String(b.name), amt, memo, user_name, card, groupId, k, months));
        }
        await env.DB.batch(stmts);
        await recordAndPush(env, { kind: 'add', name: `${b.name} (${months}개월 할부)`, amount: total, category: String(b.category), user_name, card });
        return json({ ok: true, installment_id: groupId, months, monthly_first: base + rem, monthly_rest: base });
      }

      // ── AI 설정 (앱 설정 화면에서 키 입력) ──
      //  키 값 자체는 절대 브라우저로 돌려주지 않는다. 설정됐는지와 어떤 모델을 쓰는지만 알려준다.
      if (path === '/api/settings/gemini' && request.method === 'GET') {
        const fromApp = await getSetting(env, 'gemini_key');
        return json({
          configured: !!(fromApp || env.GEMINI_API_KEY),
          source: fromApp ? 'app' : (env.GEMINI_API_KEY ? 'secret' : null),
          model: await getSetting(env, 'gemini_model'),
        });
      }

      if (path === '/api/settings/gemini' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        const key = String(b?.key || '').trim();
        if (!key) return json({ error: 'API 키를 입력해 주세요' }, 400);

        // 저장하기 전에 키가 진짜 되는지 확인한다. 안 그러면 오타난 키가 저장되고
        // 나중에 사진 찍을 때가 되어서야 실패해 원인을 알기 어렵다.
        const { models, err } = await listGeminiModels(key, env);
        if (err) return json({ error: err }, 400);
        const picked = pickGeminiModel(models);
        if (!picked) return json({ error: '이 키로 쓸 수 있는 모델이 없어요' }, 400);

        await setSetting(env, 'gemini_key', key);
        await setSetting(env, 'gemini_model', picked.model);
        return json({ ok: true, model: picked.model, candidates: picked.candidates });
      }

      // 모델만 다시 찾기 (키는 그대로)
      if (path === '/api/settings/gemini/redetect' && request.method === 'POST') {
        const key = await geminiKey(env);
        if (!key) return json({ error: '먼저 API 키를 넣어주세요' }, 400);
        const { models, err } = await listGeminiModels(key, env);
        if (err) return json({ error: err }, 400);
        const picked = pickGeminiModel(models);
        if (!picked) return json({ error: '쓸 수 있는 모델이 없어요' }, 400);
        await setSetting(env, 'gemini_model', picked.model);
        return json({ ok: true, model: picked.model, candidates: picked.candidates });
      }

      if (path === '/api/settings/gemini' && request.method === 'DELETE') {
        await env.DB.prepare(`DELETE FROM app_settings WHERE key IN ('gemini_key','gemini_model','gemini_auth_mode')`).run();
        return json({ ok: true, configured: !!env.GEMINI_API_KEY });
      }

      // 카테고리 편집(숨김/이름/이모지/순서) 오버라이드. 두 폰이 공유해야 하므로 서버(app_settings)에 둔다
      // (localStorage 금지 — 정기지출 규칙을 같은 이유로 서버로 옮긴 전례). 내장 카테고리는 클라이언트
      // 상수라, 여기엔 '덮어쓰기'만 JSON 한 덩어리로 담는다. 거래에 저장된 category(원래 key)는 안 건드린다.
      // ── 웹푸시 ──
      //  공개키는 비밀이 아니다(브라우저가 구독할 때 필요). 개인키는 secret에만 있고 절대 안 나간다.
      if (path === '/api/push/key' && request.method === 'GET') {
        return json({ key: env.VAPID_PUBLIC_KEY || null });
      }
      if (path === '/api/push/subscribe' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        const endpoint = String(b?.endpoint || '');
        const p256dh = String(b?.p256dh || '');
        const auth = String(b?.auth || '');
        if (!/^https:\/\//.test(endpoint) || !p256dh || !auth) return json({ error: '구독 정보가 올바르지 않아요' }, 400);
        await env.DB.prepare(
          `INSERT INTO push_subscriptions (endpoint, p256dh, auth, user_name) VALUES (?1,?2,?3,?4)
           ON CONFLICT(endpoint) DO UPDATE SET p256dh=excluded.p256dh, auth=excluded.auth, user_name=excluded.user_name`
        ).bind(endpoint, p256dh, auth, String(session.n || '').slice(0, 40)).run();
        const n = await env.DB.prepare(`SELECT COUNT(*) AS n FROM push_subscriptions`).first();
        return json({ ok: true, devices: n?.n || 0 });
      }
      if (path === '/api/push/unsubscribe' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        await env.DB.prepare(`DELETE FROM push_subscriptions WHERE endpoint = ?1`).bind(String(b?.endpoint || '')).run();
        return json({ ok: true });
      }
      // 서비스워커가 알림 문구를 만들려고 부른다. 가장 최근에 등록된 거래 한 건.
      if (path === '/api/push/latest' && request.method === 'GET') {
        // 마지막 '동작'(등록/삭제)을 돌려준다. 없으면(옛 배포 직후) 최신 거래로 대체.
        const raw = await getSetting(env, 'push_latest');
        if (raw) { const ev = safeParse(raw); if (ev) return json({ latest: ev }); }
        const row = await env.DB.prepare(
          `SELECT name, amount, category, user_name, card FROM transactions
           WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 1`
        ).first();
        return json({ latest: row ? { ...row, kind: 'add' } : null });
      }
      // 알림이 실제로 오는지 확인용(설정 화면의 '테스트 알림 보내기')
      if (path === '/api/push/test' && request.method === 'POST') {
        const n = await env.DB.prepare(`SELECT COUNT(*) AS n FROM push_subscriptions`).first();
        const report = await sendPushToAll(env);
        return json({ ok: true, devices: n?.n || 0, ...report });
      }

      // ── 카드 설정(결제일·이용 시작일) ──
      //  한국 카드는 '쓴 달'과 '통장에서 빠지는 달'이 다르다. 카드마다 이용기간 시작일과 결제일이
      //  달라서, 이 둘을 알아야 "이번 달 실제로 나갈 돈"을 계산할 수 있다.
      //  스키마 변경 없이 app_settings에 JSON 한 덩어리로 둔다(부부가 공유해야 하므로 서버).
      if (path === '/api/settings/cards' && request.method === 'GET') {
        const raw = await getSetting(env, 'card_settings');
        return json({ cards: raw ? safeParse(raw) : null });
      }
      if (path === '/api/settings/cards' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        const src = Array.isArray(b?.cards) ? b.cards : [];
        const out = [];
        for (const c of src.slice(0, 30)) {
          const name = String(c?.name ?? '').trim().slice(0, 20);
          const pay = Number(c?.payDay), start = Number(c?.startDay);
          if (!name) continue;
          if (!Number.isInteger(pay) || pay < 1 || pay > 31) continue;
          if (!Number.isInteger(start) || start < 1 || start > 31) continue;
          // immediate = 동백전·체크카드처럼 쓰는 즉시 빠지는 수단. 이용기간·결제일은 의미가 없다.
          const row = { name, payDay: pay, startDay: start, owner: String(c?.owner ?? '').slice(0, 40) };
          if (c?.immediate) row.immediate = true;
          out.push(row);
        }
        await setSetting(env, 'card_settings', JSON.stringify(out));
        return json({ ok: true, cards: out });
      }

      if (path === '/api/settings/categories' && request.method === 'GET') {
        const raw = await getSetting(env, 'category_overrides');
        return json({ overrides: raw ? safeParse(raw) : null });
      }
      if (path === '/api/settings/categories' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        const clean = cleanCategoryOverrides(b?.overrides);
        await setSetting(env, 'category_overrides', JSON.stringify(clean));
        return json({ ok: true, overrides: clean });
      }

      // ── 영수증 AI 인식 ──
      //  예전엔 브라우저가 Gemini를 직접 부르고 API 키를 localStorage에 뒀다. XSS 한 번이면
      //  키가 털려 사장님 구글 계정에 요금이 붙는 구조였고, 키가 없으면 prompt로 물어봤다.
      //  이제 키는 Worker secret에만 있고 브라우저는 사진만 보낸다.
      if (path === '/api/ai/receipt' && request.method === 'POST') {
        const key = await geminiKey(env);
        if (!key) {
          return json({ error: '영수증 AI 인식이 아직 설정되지 않았어요. 설정 화면에서 API 키를 넣어주세요 (사진은 그대로 저장돼요)' }, 503);
        }
        const b = await request.json().catch(() => ({}));
        const m = String(b?.image || '').match(/^data:(image\/[a-z]+);base64,([A-Za-z0-9+/=]+)$/);
        if (!m) return json({ error: '이미지 형식을 알 수 없어요' }, 400);
        const [, mime, data] = m;
        if (data.length > 8_000_000) return json({ error: '사진이 너무 커요' }, 413);

        // 카테고리 목록은 앱이 보내온 걸 쓴다. 여기에 하드코딩하면 앱의 CATEGORIES와 어긋나서,
        // 모델이 없는 카테고리('주거' 등)를 돌려주고 앱은 그걸 버려 사용자 눈엔 인식 실패로 보인다.
        const cats = Array.isArray(b?.categories) && b.categories.length
          ? b.categories.filter(c => typeof c === 'string' && c.length <= 40).slice(0, 30)
          : ['기타'];

        const g = await callGemini(env, key, {
          contents: [{ parts: [
            { inline_data: { mime_type: mime, data } },
            { text: '이 영수증 사진을 분석해서 JSON만 출력해. 다른 말 금지.\n' +
                    '형식: {"name":"가게명","amount":숫자,"category":"아래 목록 중 정확히 하나"}\n' +
                    '카테고리 목록: ' + cats.join(' | ') + '\n' +
                    'amount는 총 결제금액의 숫자만(쉼표·원 표시 없이). 못 읽으면 amount를 0으로.' },
          ] }],
          generationConfig: { temperature: 0.1, maxOutputTokens: 200 },
        });
        if (g.err) return json({ error: g.err }, 502);

        const text = g.text || '';
        const jm = text.match(/\{[\s\S]*\}/); // 모델이 ```json 같은 걸 붙여도 건져낸다
        if (!jm) return json({ error: '영수증을 알아보지 못했어요. 직접 입력해 주세요' }, 422);
        let parsed;
        try { parsed = JSON.parse(jm[0]); } catch { return json({ error: '영수증을 알아보지 못했어요. 직접 입력해 주세요' }, 422); }

        const amount = Math.floor(Number(parsed.amount) || 0);
        return json({
          name: String(parsed.name ?? '').slice(0, 100),
          amount: amount > 0 && amount < 100000000000 ? amount : 0,
          category: String(parsed.category ?? '').slice(0, 40),
        });
      }

      // ── 소비 패턴 분석 (통계 화면) ──
      //  앱이 이미 집계한 요약문만 보내온다. 원본 거래를 통째로 보내지 않으므로 외부로 나가는 정보가 적다.
      if (path === '/api/ai/analyze' && request.method === 'POST') {
        const key = await geminiKey(env);
        if (!key) return json({ error: 'AI 분석이 아직 설정되지 않았어요. 설정 화면에서 API 키를 넣어주세요' }, 503);
        const b = await request.json().catch(() => ({}));
        const summary = String(b?.summary || '');
        if (!summary || summary.length > 4000) return json({ error: '분석할 내용이 올바르지 않아요' }, 400);

        const g = await callGemini(env, key, {
          contents: [{ parts: [{ text: summary }] }],
          generationConfig: { temperature: 0.7, maxOutputTokens: 600 },
        });
        if (g.err) return json({ error: g.err }, 502);
        return json({ text: g.text || '' });
      }

      // ── 영수증 사진 (필요할 때만 한 장씩) ──
      if (path.startsWith('/api/tx/') && path.endsWith('/photo') && request.method === 'GET') {
        const id = decodeURIComponent(path.slice('/api/tx/'.length, -'/photo'.length));
        const row = await env.DB.prepare(`SELECT photo_url FROM transactions WHERE id = ?1`).bind(id).first();
        if (!row) return json({ error: '거래를 찾지 못했어요' }, 404);
        return json({ photo_url: row.photo_url });
      }

      // ── 특정 월 영수증 갤러리 (목록만; 사진은 각 썸네일이 /api/tx/:id/photo로 지연 로드) ──
      //  photo_url을 여기서 다 실으면 사진이 쌓일수록 응답이 수 MB~수십 MB가 되어 셀룰러에서 느리고
      //  큰 달은 아예 실패한다. 목록엔 메타만, 이미지는 화면에 보일 때 한 장씩.
      if (path === '/api/receipts' && request.method === 'GET') {
        const month = url.searchParams.get('month');
        if (!isMonth(month)) return json({ error: '월 형식이 올바르지 않아요' }, 400);
        const r = await env.DB.prepare(
          `SELECT id, date, name, amount FROM transactions
           WHERE photo_url IS NOT NULL AND date LIKE ?1 AND deleted_at IS NULL ORDER BY date DESC`
        ).bind(month + '-%').all();
        return json({ receipts: r.results ?? [] });
      }

      // ── 휴지통 목록 (소프트 삭제된 거래) ──
      if (path === '/api/trash' && request.method === 'GET') {
        const r = await env.DB.prepare(
          `SELECT ${TX_COLS}, deleted_at FROM transactions WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC`
        ).all();
        return json({ transactions: r.results ?? [] });
      }

      // ── 휴지통 비우기 (전체 완전삭제) ──
      if (path === '/api/trash' && request.method === 'DELETE') {
        const r = await env.DB.prepare(`DELETE FROM transactions WHERE deleted_at IS NOT NULL`).run();
        return json({ cleared: r.meta.changes });
      }

      // ── 휴지통에서 한 건 완전삭제 ──
      if (path.startsWith('/api/trash/') && request.method === 'DELETE') {
        const id = decodeURIComponent(path.slice('/api/trash/'.length));
        const r = await env.DB.prepare(`DELETE FROM transactions WHERE id = ?1 AND deleted_at IS NOT NULL`).bind(id).run();
        if (!r.meta.changes) return json({ error: '삭제할 거래를 찾지 못했어요' }, 404);
        return json({ ok: true });
      }

      // ── 할부 전체 취소 (그룹 소프트삭제) ── 남은 회차까지 한 번에 휴지통으로.
      if (path.startsWith('/api/installment/') && request.method === 'DELETE') {
        const gid = decodeURIComponent(path.slice('/api/installment/'.length));
        const one = await env.DB.prepare(
          `SELECT name, amount, category, user_name, card, installment_months FROM transactions WHERE installment_id = ?1 AND deleted_at IS NULL LIMIT 1`
        ).bind(gid).first();
        const r = await env.DB.prepare(
          `UPDATE transactions SET deleted_at = datetime('now') WHERE installment_id = ?1 AND deleted_at IS NULL`
        ).bind(gid).run();
        if (!r.meta.changes) return json({ error: '취소할 할부를 찾지 못했어요' }, 404);
        if (one) await recordAndPush(env, { kind: 'delete', name: `${one.name} (할부 취소)`, amount: one.amount, category: one.category, user_name: one.user_name, card: one.card });
        return json({ ok: true, cancelled: r.meta.changes });
      }

      // ── 휴지통에서 복원 ──
      //  /api/tx/:id/restore 는 아래 txId(수정/삭제) 파싱보다 먼저 처리해야 한다
      //  (안 그러면 id가 'xxx/restore'로 잡힌다).
      if (path.startsWith('/api/tx/') && path.endsWith('/restore') && request.method === 'POST') {
        const id = decodeURIComponent(path.slice('/api/tx/'.length, -'/restore'.length));
        const r = await env.DB.prepare(
          `UPDATE transactions SET deleted_at = NULL WHERE id = ?1 AND deleted_at IS NOT NULL`
        ).bind(id).run();
        if (!r.meta.changes) return json({ error: '복원할 거래를 찾지 못했어요' }, 404);
        const row = await env.DB.prepare(`SELECT ${TX_COLS} FROM transactions WHERE id = ?1`).bind(id).first();
        return json({ tx: row });
      }

      // ── 거래 수정 / 삭제 ──
      const txId = path.startsWith('/api/tx/') ? decodeURIComponent(path.slice('/api/tx/'.length)) : null;

      if (txId && request.method === 'PATCH') {
        const { tx, err } = cleanTx(await request.json().catch(() => ({})));
        if (err) return json({ error: err }, 400);
        // 휴지통에 있는 건 수정 대상이 아니다(deleted_at IS NULL).
        const r = await env.DB.prepare(
          `UPDATE transactions SET date=?1, type=?2, category=?3, name=?4, amount=?5, memo=?6, user_name=?7,
                  photo_url = CASE WHEN ?8 = 1 THEN ?9 ELSE photo_url END, card=?11
           WHERE id = ?10 AND deleted_at IS NULL`
        ).bind(tx.date, tx.type, tx.category, tx.name, tx.amount, tx.memo, tx.user_name,
               tx._setPhoto, tx.photo_url, txId, tx.card).run();
        if (!r.meta.changes) return json({ error: '수정할 거래를 찾지 못했어요' }, 404);
        const row = await env.DB.prepare(`SELECT ${TX_COLS} FROM transactions WHERE id = ?1`).bind(txId).first();
        return json({ tx: row });
      }

      // 삭제는 '소프트 삭제' — 바로 지우지 않고 deleted_at만 찍는다. 30일 뒤 /api/data 로드 때 완전삭제된다.
      // 실수로 지워도 휴지통에서 되살릴 수 있게. (예전엔 하드 삭제라 복구가 아예 불가능했다)
      if (txId && request.method === 'DELETE') {
        // 삭제 전 정보를 미리 읽어둔다(알림 문구용). 삭제 후엔 화면에서 사라진다.
        const gone = await env.DB.prepare(
          `SELECT name, amount, category, user_name, card FROM transactions WHERE id = ?1 AND deleted_at IS NULL`
        ).bind(txId).first();
        const r = await env.DB.prepare(
          `UPDATE transactions SET deleted_at = datetime('now') WHERE id = ?1 AND deleted_at IS NULL`
        ).bind(txId).run();
        if (!r.meta.changes) return json({ error: '삭제할 거래를 찾지 못했어요' }, 404);
        // 삭제도 두 사람에게 알림.
        if (gone) await recordAndPush(env, { kind: 'delete', ...gone });
        return json({ ok: true });
      }

      // ── 정기 지출 규칙 ──
      if (path === '/api/recurring' && request.method === 'GET') {
        const r = await env.DB.prepare(`SELECT id, name, amount, category, day FROM recurring_rules ORDER BY day`).all();
        return json({ rules: r.results ?? [] });
      }

      if (path === '/api/recurring' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        const amount = Number(b?.amount), day = Number(b?.day);
        if (!b?.name || String(b.name).length > 100) return json({ error: '이름을 확인해 주세요' }, 400);
        if (!b?.category || String(b.category).length > 40) return json({ error: '카테고리를 확인해 주세요' }, 400);
        if (!Number.isInteger(amount) || amount <= 0) return json({ error: '금액은 1원 이상의 정수여야 해요' }, 400);
        if (!Number.isInteger(day) || day < 1 || day > 31) return json({ error: '날짜는 1~31 사이여야 해요' }, 400);
        const id = crypto.randomUUID();
        await env.DB.prepare(
          `INSERT INTO recurring_rules (id, name, amount, category, day) VALUES (?1,?2,?3,?4,?5)`
        ).bind(id, String(b.name), amount, String(b.category), day).run();
        const r = await env.DB.prepare(`SELECT id, name, amount, category, day FROM recurring_rules ORDER BY day`).all();
        return json({ rules: r.results ?? [] });
      }

      if (path.startsWith('/api/recurring/') && request.method === 'DELETE') {
        const id = decodeURIComponent(path.slice('/api/recurring/'.length));
        await env.DB.prepare(`DELETE FROM recurring_applied WHERE rule_id = ?1`).bind(id).run();
        const d = await env.DB.prepare(`DELETE FROM recurring_rules WHERE id = ?1`).bind(id).run();
        if (!d.meta.changes) return json({ error: '정기 지출을 찾지 못했어요' }, 404);
        const r = await env.DB.prepare(`SELECT id, name, amount, category, day FROM recurring_rules ORDER BY day`).all();
        return json({ rules: r.results ?? [] });
      }

      // ── 정기 지출 자동 등록 ──
      //  판단을 서버가 한다. 앱이 "오늘 며칠인지"만 알려주면(서버 시각은 UTC라 한국 날짜와 다를 수 있다)
      //  나머지는 여기서 원자적으로 처리한다.
      //  recurring_applied에 (규칙,달)을 INSERT OR IGNORE 하는 게 곧 잠금이다:
      //   - 이미 등록한 달이면 changes=0 → 건너뛴다. 사용자가 그 거래를 지웠어도 다시 만들지 않는다.
      //     (예전엔 지우면 즉시 되살아나서 삭제가 아예 불가능했다)
      //   - 부부가 같은 순간에 앱을 열어도 한쪽만 changes=1이라 중복이 생기지 않는다.
      if (path === '/api/recurring/apply' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        const today = b?.today;
        if (!isDate(today)) return json({ error: '날짜가 올바르지 않아요' }, 400);
        const ym = today.slice(0, 7);
        const todayDay = Number(today.slice(8, 10));
        const lastDay = new Date(Date.UTC(Number(ym.slice(0, 4)), Number(ym.slice(5, 7)), 0)).getUTCDate();

        const rules = (await env.DB.prepare(`SELECT id, name, amount, category, day FROM recurring_rules`).all()).results ?? [];
        const created = [];
        for (const rule of rules) {
          const day = Math.min(rule.day, lastDay); // 31일 규칙이 30일 달에서 없는 날짜가 되지 않도록
          if (day > todayDay) continue;            // 아직 그날이 안 됨
          const txId = crypto.randomUUID();
          const dateStr = `${ym}-${String(day).padStart(2, '0')}`;

          // claim과 거래 삽입을 batch(한 트랜잭션)로 묶는다. 예전엔 claim 먼저 넣고 그 다음 거래를
          // 넣었는데, 그 사이에 워커가 죽으면 claim만 남아 그 달이 영구 누락됐다(재실행해도 이미
          // 등록됨으로 판단). batch는 둘 다 커밋되거나 둘 다 안 된다.
          //   1) (규칙,달)을 tx_id와 함께 선점(INSERT OR IGNORE). 이미 있으면 무시된다.
          //   2) 거래는 '이 호출의 선점이 이긴 경우에만' 넣는다 — 저장된 tx_id가 내 txId와 같을 때.
          //      부부가 동시에 열면 한쪽만 선점에 성공하므로 중복 거래가 안 생긴다.
          let res;
          try {
            res = await env.DB.batch([
              env.DB.prepare(`INSERT OR IGNORE INTO recurring_applied (rule_id, ym, tx_id) VALUES (?1,?2,?3)`)
                    .bind(rule.id, ym, txId),
              env.DB.prepare(
                `INSERT INTO transactions (id,date,type,category,name,amount,memo,photo_url,is_recurring,user_name)
                 SELECT ?1,?2,'expense',?3,?4,?5,'자동 등록',NULL,1,''
                 WHERE (SELECT tx_id FROM recurring_applied WHERE rule_id=?6 AND ym=?7) = ?1`
              ).bind(txId, dateStr, rule.category, rule.name, rule.amount, rule.id, ym),
            ]);
          } catch (e) {
            console.warn('정기 지출 자동 등록 실패:', rule.name, String(e?.message || e));
            continue;
          }
          if (!res?.[1]?.meta?.changes) continue;  // 이미 등록됐거나 선점 못 함 → 새로 만든 거 없음
          const row = await env.DB.prepare(`SELECT ${TX_COLS} FROM transactions WHERE id = ?1`).bind(txId).first();
          if (row) created.push(row);
        }
        return json({ created });
      }

      // ── 예산 저장 ──
      if (path === '/api/budget' && request.method === 'PUT') {
        const b = await request.json().catch(() => ({}));
        const amount = Number(b?.amount);
        if (!isMonth(b?.month)) return json({ error: '월 형식이 올바르지 않아요' }, 400);
        if (!b?.category || String(b.category).length > 40) return json({ error: '카테고리를 확인해 주세요' }, 400);
        if (!Number.isInteger(amount) || amount <= 0) return json({ error: '금액은 1원 이상의 정수여야 해요' }, 400);

        await env.DB.prepare(
          `INSERT INTO budgets (id, month, category, amount) VALUES (?1,?2,?3,?4)
           ON CONFLICT(month, category) DO UPDATE SET amount = excluded.amount`
        ).bind(crypto.randomUUID(), b.month, String(b.category), amount).run();

        const r = await env.DB.prepare(`SELECT id, month, category, amount FROM budgets WHERE month = ?1`).bind(b.month).all();
        return json({ budgets: r.results ?? [] });
      }

      // ── 특정 월 영수증 사진 일괄 삭제 (거래는 유지) ──
      if (path === '/api/receipts/clear' && request.method === 'POST') {
        const month = url.searchParams.get('month');
        if (!isMonth(month)) return json({ error: '월 형식이 올바르지 않아요' }, 400);
        const r = await env.DB.prepare(
          `UPDATE transactions SET photo_url = NULL WHERE photo_url IS NOT NULL AND date LIKE ?1 AND deleted_at IS NULL`
        ).bind(month + '-%').run();
        return json({ cleared: r.meta.changes });
      }

      // ── 카테고리 (사용자 추가) ──
      //  내장 카테고리는 앱(클라이언트)에 있고, 여기엔 사용자가 추가한 것만 저장한다.
      //  거래의 category는 문자열로 박혀 있어, 카테고리를 지워도 기존 거래는 그 이름 그대로 남는다
      //  (앱은 모르는 카테고리를 📦로 안전하게 그린다).
      if (path === '/api/categories' && request.method === 'GET') {
        const r = await env.DB.prepare(`SELECT id, type, name, emoji, sort FROM categories ORDER BY type, sort, created_at`).all();
        return json({ categories: r.results ?? [] });
      }
      if (path === '/api/categories' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        const type = b?.type;
        const name = String(b?.name ?? '').trim();
        const emoji = (String(b?.emoji ?? '').trim() || '🏷️');
        if (type !== 'income' && type !== 'expense') return json({ error: '수입/지출 구분이 올바르지 않아요' }, 400);
        if (!name || name.length > 20) return json({ error: '카테고리 이름을 확인해 주세요 (1~20자)' }, 400);
        if (emoji.length > 8) return json({ error: '이모지를 확인해 주세요' }, 400);
        try {
          await env.DB.prepare(`INSERT INTO categories (id, type, name, emoji, sort) VALUES (?1,?2,?3,?4,?5)`)
            .bind(crypto.randomUUID(), type, name, emoji, Date.now() % 1000000000).run();
        } catch (e) {
          if (/UNIQUE/i.test(String(e?.message || e))) return json({ error: '이미 있는 카테고리예요' }, 409);
          throw e;
        }
        const r = await env.DB.prepare(`SELECT id, type, name, emoji, sort FROM categories ORDER BY type, sort, created_at`).all();
        return json({ categories: r.results ?? [] });
      }
      if (path.startsWith('/api/categories/') && request.method === 'DELETE') {
        const id = decodeURIComponent(path.slice('/api/categories/'.length));
        const d = await env.DB.prepare(`DELETE FROM categories WHERE id = ?1`).bind(id).run();
        if (!d.meta.changes) return json({ error: '카테고리를 찾지 못했어요' }, 404);
        const r = await env.DB.prepare(`SELECT id, type, name, emoji, sort FROM categories ORDER BY type, sort, created_at`).all();
        return json({ categories: r.results ?? [] });
      }

      // ── 전체 백업 (사진 포함) ──
      //  JSON 한 덩어리로 내려준다. 목록 API와 달리 photo_url(base64)까지 포함하므로 응답이 클 수 있다.
      //  휴지통(deleted_at)은 백업에서 제외 — 복원 때 지운 게 되살아나면 곤란하다.
      if (path === '/api/backup' && request.method === 'GET') {
        const tx = await env.DB.prepare(
          `SELECT id, created_at, date, type, category, name, amount, memo, photo_url, is_recurring, user_name,
                  card, installment_id, installment_seq, installment_months
           FROM transactions WHERE deleted_at IS NULL ORDER BY date`
        ).all();
        const bud = await env.DB.prepare(`SELECT id, month, category, amount FROM budgets`).all();
        const rec = await env.DB.prepare(`SELECT id, name, amount, category, day FROM recurring_rules`).all();
        const cat = await env.DB.prepare(`SELECT id, type, name, emoji, sort FROM categories`).all();
        const catOv = await getSetting(env, 'category_overrides');
        const cardSet = await getSetting(env, 'card_settings');
        return json({
          version: 1,
          exported_at: new Date().toISOString(),
          transactions: tx.results ?? [],
          budgets: bud.results ?? [],
          recurring_rules: rec.results ?? [],
          categories: cat.results ?? [],
          category_overrides: catOv ? safeParse(catOv) : null,
          card_settings: cardSet ? safeParse(cardSet) : null,
        });
      }

      // ── 백업 복원 ──
      //  같은 id는 INSERT OR IGNORE로 건너뛴다 — 같은 파일을 두 번 넣어도 중복이 안 생긴다(추가만, 삭제 없음).
      //  형식이 어긋난 거래는 cleanTx로 걸러 조용히 건너뛴다(전체가 실패하지 않도록).
      if (path === '/api/restore' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        const counts = { transactions: 0, budgets: 0, recurring_rules: 0, categories: 0, skipped: 0 };

        for (const t of (Array.isArray(b?.transactions) ? b.transactions : [])) {
          const { tx, err } = cleanTx(t);
          if (err) { counts.skipped++; continue; }
          const id = (typeof t.id === 'string' && t.id) ? t.id : crypto.randomUUID();
          const instId  = typeof t.installment_id === 'string' ? t.installment_id : null;
          const instSeq = Number.isInteger(t.installment_seq) ? t.installment_seq : null;
          const instN   = Number.isInteger(t.installment_months) ? t.installment_months : null;
          try {
            const r = await env.DB.prepare(
              `INSERT OR IGNORE INTO transactions (id,date,type,category,name,amount,memo,photo_url,is_recurring,user_name,card,installment_id,installment_seq,installment_months)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)`
            ).bind(id, tx.date, tx.type, tx.category, tx.name, tx.amount, tx.memo, tx.photo_url, tx.is_recurring, tx.user_name, tx.card, instId, instSeq, instN).run();
            if (r.meta.changes) counts.transactions++;
          } catch (e) { counts.skipped++; }
        }
        for (const bd of (Array.isArray(b?.budgets) ? b.budgets : [])) {
          try {
            const amount = Number(bd?.amount);
            if (!isMonth(bd?.month) || !Number.isInteger(amount) || amount <= 0 || !bd?.category) continue;
            const r = await env.DB.prepare(
              `INSERT OR IGNORE INTO budgets (id, month, category, amount) VALUES (?1,?2,?3,?4)`
            ).bind(bd.id || crypto.randomUUID(), bd.month, String(bd.category), amount).run();
            if (r.meta.changes) counts.budgets++;
          } catch (e) {}
        }
        for (const rl of (Array.isArray(b?.recurring_rules) ? b.recurring_rules : [])) {
          try {
            const amount = Number(rl?.amount), day = Number(rl?.day);
            if (!rl?.name || !Number.isInteger(amount) || amount <= 0 || !Number.isInteger(day) || day < 1 || day > 31) continue;
            const r = await env.DB.prepare(
              `INSERT OR IGNORE INTO recurring_rules (id, name, amount, category, day) VALUES (?1,?2,?3,?4,?5)`
            ).bind(rl.id || crypto.randomUUID(), String(rl.name), amount, String(rl.category || '기타'), day).run();
            if (r.meta.changes) counts.recurring_rules++;
          } catch (e) {}
        }
        for (const c of (Array.isArray(b?.categories) ? b.categories : [])) {
          try {
            if ((c?.type !== 'income' && c?.type !== 'expense') || !c?.name || String(c.name).length > 20) continue;
            const r = await env.DB.prepare(
              `INSERT OR IGNORE INTO categories (id, type, name, emoji, sort) VALUES (?1,?2,?3,?4,?5)`
            ).bind(c.id || crypto.randomUUID(), c.type, String(c.name), String(c.emoji || '🏷️').slice(0, 8), Number(c.sort) || 0).run();
            if (r.meta.changes) counts.categories++;
          } catch (e) {}
        }
        // 카테고리 편집(숨김/이름/순서). 백업에 있으면 되살린다 — 안 그러면 복원 한 번에 편집이 날아간다.
        if (Array.isArray(b?.card_settings)) {
          try { await setSetting(env, 'card_settings', JSON.stringify(b.card_settings)); } catch (e) {}
        }
        if (b?.category_overrides && typeof b.category_overrides === 'object') {
          try { await setSetting(env, 'category_overrides', JSON.stringify(cleanCategoryOverrides(b.category_overrides))); } catch (e) {}
        }
        return json({ ok: true, counts });
      }

      return json({ error: '없는 주소예요' }, 404);
    } catch (e) {
      // 실패를 조용히 삼키지 않는다. 앱이 이 메시지를 그대로 사용자에게 보여준다.
      const msg = String(e?.message || e);
      // 위 검증을 빠져나간 잘못된 입력이 DB 제약에 걸린 경우. 서버 오류(500)가 아니라 입력 오류(400)이고,
      // 사용자에게 raw SQL 문구를 보여줄 이유가 없다.
      if (/SQLITE_CONSTRAINT|CHECK constraint|UNIQUE constraint/i.test(msg)) {
        console.warn('제약 위반:', msg);
        return json({ error: '입력한 내용을 저장할 수 없어요. 날짜와 금액을 확인해 주세요' }, 400);
      }
      return json({ error: msg }, 500);
    }
  },
};
