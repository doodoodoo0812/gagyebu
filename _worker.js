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

async function issueToken(name, secret) {
  const payload = b64url(enc.encode(JSON.stringify({ n: String(name || '').slice(0, 40), exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SEC })));
  return `${payload}.${await hmac(payload, secret)}`;
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
                 (photo_url IS NOT NULL) AS has_photo`;

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
      if (path === '/api/login' && request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        // 무차별 대입 속도를 떨어뜨린다. 비밀번호가 하나뿐이라 이 지연이 유일한 방어선이다.
        await new Promise((r) => setTimeout(r, 400));
        if (!safeEqual(b?.password ?? '', env.APP_PASSWORD)) {
          return json({ error: '비밀번호가 맞지 않아요' }, 401);
        }
        const name = String(b?.name ?? '').slice(0, 40);
        return json({ token: await issueToken(name, env.SESSION_SECRET), name });
      }

      // ── 이하 전부 인증 필요 ──
      const auth = request.headers.get('Authorization') || '';
      const session = await verifyToken(auth.replace(/^Bearer\s+/i, ''), env.SESSION_SECRET);
      if (!session) return json({ error: '로그인이 필요해요' }, 401);

      if (path === '/api/me' && request.method === 'GET') {
        return json({ name: session.n });
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

        const tx = await env.DB.prepare(
          `SELECT ${TX_COLS} FROM transactions WHERE date >= ?1 AND date < ?2 ORDER BY date DESC`
        ).bind(from, to).all();

        const bud = await env.DB.prepare(
          `SELECT id, month, category, amount FROM budgets WHERE month = ?1`
        ).bind(month).all();

        return json({ transactions: tx.results ?? [], budgets: bud.results ?? [] });
      }

      // ── 전체 거래 (엑셀 '전체 내보내기' 전용) ──
      //  화면용 배열은 6개월치뿐이라, '전체'를 자처하는 파일을 그걸로 만들면 안 된다.
      if (path === '/api/tx/all' && request.method === 'GET') {
        const r = await env.DB.prepare(`SELECT ${TX_COLS} FROM transactions ORDER BY date DESC`).all();
        return json({ transactions: r.results ?? [] });
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
            `SELECT ${TX_COLS} FROM transactions WHERE date = ?1 AND name = ?2 AND is_recurring = 1`
          ).bind(tx.date, tx.name).first();
          return json({ tx: row });
        }

        await env.DB.prepare(
          `INSERT INTO transactions (id,date,type,category,name,amount,memo,photo_url,is_recurring,user_name)
           VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0,?9)`
        ).bind(id, tx.date, tx.type, tx.category, tx.name, tx.amount, tx.memo, tx.photo_url, tx.user_name).run();
        const row = await env.DB.prepare(`SELECT ${TX_COLS} FROM transactions WHERE id = ?1`).bind(id).first();
        return json({ tx: row });
      }

      // ── 영수증 AI 인식 ──
      //  예전엔 브라우저가 Gemini를 직접 부르고 API 키를 localStorage에 뒀다. XSS 한 번이면
      //  키가 털려 사장님 구글 계정에 요금이 붙는 구조였고, 키가 없으면 prompt로 물어봤다.
      //  이제 키는 Worker secret에만 있고 브라우저는 사진만 보낸다.
      if (path === '/api/ai/receipt' && request.method === 'POST') {
        if (!env.GEMINI_API_KEY) {
          return json({ error: '영수증 AI 인식이 아직 설정되지 않았어요. 사진은 그대로 저장되니 금액만 직접 넣어주세요' }, 503);
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

        // 응답이 안 오면 화면이 '분석 중…'에서 영원히 멈춘다. 반드시 끊는다.
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 25000);
        let g;
        try {
          const res = await fetch(
            'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=' +
              encodeURIComponent(env.GEMINI_API_KEY),
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              signal: ctrl.signal,
              body: JSON.stringify({
                contents: [{ parts: [
                  { inline_data: { mime_type: mime, data } },
                  { text: '이 영수증 사진을 분석해서 JSON만 출력해. 다른 말 금지.\n' +
                          '형식: {"name":"가게명","amount":숫자,"category":"아래 목록 중 정확히 하나"}\n' +
                          '카테고리 목록: ' + cats.join(' | ') + '\n' +
                          'amount는 총 결제금액의 숫자만(쉼표·원 표시 없이). 못 읽으면 amount를 0으로.' },
                ] }],
                generationConfig: { temperature: 0.1, maxOutputTokens: 200 },
              }),
            }
          );
          g = await res.json();
        } catch (e) {
          return json({ error: e?.name === 'AbortError' ? 'AI 응답이 너무 늦어요. 직접 입력해 주세요' : 'AI 호출 실패: ' + e.message }, 504);
        } finally {
          clearTimeout(timer);
        }

        if (g?.error) {
          console.warn('Gemini 오류:', JSON.stringify(g.error).slice(0, 300));
          return json({ error: 'AI 인식에 실패했어요. 직접 입력해 주세요' }, 502);
        }
        const text = g?.candidates?.[0]?.content?.parts?.[0]?.text || '';
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
        if (!env.GEMINI_API_KEY) return json({ error: 'AI 분석이 아직 설정되지 않았어요' }, 503);
        const b = await request.json().catch(() => ({}));
        const summary = String(b?.summary || '');
        if (!summary || summary.length > 4000) return json({ error: '분석할 내용이 올바르지 않아요' }, 400);

        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 25000);
        let g;
        try {
          const res = await fetch(
            'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=' +
              encodeURIComponent(env.GEMINI_API_KEY),
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              signal: ctrl.signal,
              body: JSON.stringify({
                contents: [{ parts: [{ text: summary }] }],
                generationConfig: { temperature: 0.7, maxOutputTokens: 600 },
              }),
            }
          );
          g = await res.json();
        } catch (e) {
          return json({ error: e?.name === 'AbortError' ? 'AI 응답이 너무 늦어요' : 'AI 호출 실패: ' + e.message }, 504);
        } finally {
          clearTimeout(timer);
        }
        if (g?.error) {
          console.warn('Gemini 오류:', JSON.stringify(g.error).slice(0, 300));
          return json({ error: 'AI 분석에 실패했어요' }, 502);
        }
        return json({ text: g?.candidates?.[0]?.content?.parts?.[0]?.text || '' });
      }

      // ── 영수증 사진 (필요할 때만 한 장씩) ──
      if (path.startsWith('/api/tx/') && path.endsWith('/photo') && request.method === 'GET') {
        const id = decodeURIComponent(path.slice('/api/tx/'.length, -'/photo'.length));
        const row = await env.DB.prepare(`SELECT photo_url FROM transactions WHERE id = ?1`).bind(id).first();
        if (!row) return json({ error: '거래를 찾지 못했어요' }, 404);
        return json({ photo_url: row.photo_url });
      }

      // ── 특정 월 영수증 갤러리 (사용자가 갤러리를 열 때만) ──
      if (path === '/api/receipts' && request.method === 'GET') {
        const month = url.searchParams.get('month');
        if (!isMonth(month)) return json({ error: '월 형식이 올바르지 않아요' }, 400);
        const r = await env.DB.prepare(
          `SELECT id, date, name, amount, photo_url FROM transactions
           WHERE photo_url IS NOT NULL AND date LIKE ?1 ORDER BY date DESC`
        ).bind(month + '-%').all();
        return json({ receipts: r.results ?? [] });
      }

      // ── 거래 수정 / 삭제 ──
      const txId = path.startsWith('/api/tx/') ? decodeURIComponent(path.slice('/api/tx/'.length)) : null;

      if (txId && request.method === 'PATCH') {
        const { tx, err } = cleanTx(await request.json().catch(() => ({})));
        if (err) return json({ error: err }, 400);
        const r = await env.DB.prepare(
          `UPDATE transactions SET date=?1, type=?2, category=?3, name=?4, amount=?5, memo=?6, user_name=?7,
                  photo_url = CASE WHEN ?8 = 1 THEN ?9 ELSE photo_url END
           WHERE id = ?10`
        ).bind(tx.date, tx.type, tx.category, tx.name, tx.amount, tx.memo, tx.user_name,
               tx._setPhoto, tx.photo_url, txId).run();
        if (!r.meta.changes) return json({ error: '수정할 거래를 찾지 못했어요' }, 404);
        const row = await env.DB.prepare(`SELECT ${TX_COLS} FROM transactions WHERE id = ?1`).bind(txId).first();
        return json({ tx: row });
      }

      if (txId && request.method === 'DELETE') {
        const r = await env.DB.prepare(`DELETE FROM transactions WHERE id = ?1`).bind(txId).run();
        if (!r.meta.changes) return json({ error: '삭제할 거래를 찾지 못했어요' }, 404);
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
          const claim = await env.DB.prepare(
            `INSERT OR IGNORE INTO recurring_applied (rule_id, ym) VALUES (?1,?2)`
          ).bind(rule.id, ym).run();
          if (!claim.meta.changes) continue;       // 이미 이 달에 등록했음

          const txId = crypto.randomUUID();
          try {
            await env.DB.prepare(
              `INSERT INTO transactions (id,date,type,category,name,amount,memo,photo_url,is_recurring,user_name)
               VALUES (?1,?2,'expense',?3,?4,?5,'자동 등록',NULL,1,'')`
            ).bind(txId, `${ym}-${String(day).padStart(2, '0')}`, rule.category, rule.name, rule.amount).run();
          } catch (e) {
            // 거래를 못 넣었으면 등록 표시도 되돌린다. 안 그러면 영영 등록되지 않는다.
            await env.DB.prepare(`DELETE FROM recurring_applied WHERE rule_id=?1 AND ym=?2`).bind(rule.id, ym).run();
            console.warn('정기 지출 자동 등록 실패:', rule.name, String(e?.message || e));
            continue;
          }
          await env.DB.prepare(`UPDATE recurring_applied SET tx_id=?1 WHERE rule_id=?2 AND ym=?3`).bind(txId, rule.id, ym).run();
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
          `UPDATE transactions SET photo_url = NULL WHERE photo_url IS NOT NULL AND date LIKE ?1`
        ).bind(month + '-%').run();
        return json({ cleared: r.meta.changes });
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
