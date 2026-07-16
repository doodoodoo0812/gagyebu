-- 우리집 가계부 — Cloudflare D1 스키마
-- 적용: npx wrangler d1 execute gagyebu --remote --file=schema.sql
--
-- SQLite에는 날짜 타입이 없어 '2026-04-31' 같은 값도 그냥 문자열로 들어간다.
-- 앱 전체가 date를 'YYYY-MM-DD' 문자열로 두고 startsWith(월)로 거르기 때문에,
-- 형식이 깨진 날짜 하나가 그 달 집계를 통째로 어긋나게 만든다. 그래서 DB에서 막는다.
--   - GLOB      : 자릿수·0패딩 강제 (startsWith 필터가 의존하는 형식)
--   - IS date() : 달력에 실재하는 날짜인지 (4/31, 13월, 평년 2/29 차단, 윤년 2/29 통과)
--     ※ SQLite CHECK은 결과가 NULL이면 통과시키므로 '='가 아니라 NULL-안전한 'IS'를 써야 한다.

CREATE TABLE transactions (
  id           TEXT PRIMARY KEY,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  date         TEXT NOT NULL
                 CHECK (date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]')
                 CHECK (date IS date(date)),
  type         TEXT NOT NULL CHECK (type IN ('income','expense')),
  category     TEXT NOT NULL CHECK (length(category) BETWEEN 1 AND 40),
  name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  amount       INTEGER NOT NULL CHECK (amount > 0 AND amount < 100000000000),
  memo         TEXT NOT NULL DEFAULT '' CHECK (length(memo) <= 500),
  photo_url    TEXT,
  is_recurring INTEGER NOT NULL DEFAULT 0 CHECK (is_recurring IN (0,1)),
  user_name    TEXT NOT NULL DEFAULT '' CHECK (length(user_name) <= 40)
);

CREATE INDEX idx_tx_date ON transactions(date);

-- 정기 지출 중복 방지.
-- 앱의 "이미 등록했나?" 검사는 읽고-나서-쓰기라 원자적이지 않다. 부부가 같은 날 동시에
-- 앱을 열면 둘 다 "없음"으로 읽고 둘 다 넣어 관리비가 두 번 잡힌다. 코드로는 못 막으므로
-- DB가 막는다. 일반 거래는 대상이 아니므로(같은 날 같은 카페를 두 번 갈 수 있다) 부분 인덱스.
CREATE UNIQUE INDEX idx_tx_recurring_once
  ON transactions(date, name) WHERE is_recurring = 1;

CREATE TABLE budgets (
  id         TEXT PRIMARY KEY,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  month      TEXT NOT NULL
               CHECK (month GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]')
               CHECK (date(month || '-01') IS NOT NULL),
  category   TEXT NOT NULL CHECK (length(category) BETWEEN 1 AND 40),
  amount     INTEGER NOT NULL CHECK (amount > 0 AND amount < 100000000000),
  UNIQUE(month, category)
);
