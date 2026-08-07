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
  user_name    TEXT NOT NULL DEFAULT '' CHECK (length(user_name) <= 40),
  -- 소프트 삭제. NULL이면 정상, 값이 있으면 '휴지통'에 있는 거래(삭제한 시각).
  -- 삭제를 바로 지우지 않고 이 칸만 찍어, 실수로 지워도 되살릴 수 있게 한다.
  -- 조회는 전부 deleted_at IS NULL로 거르고, 30일 지난 건 데이터 로드 때 완전삭제한다.
  deleted_at   TEXT,
  -- 카드사(선택). 일시불에도 기록 가능.
  card         TEXT,
  -- 무이자 할부. 등록 때 N개월치를 각 달에 미리 만들고 같은 installment_id로 묶는다(한 번에 취소).
  installment_id     TEXT,      -- 그룹 키. NULL이면 할부 아님
  installment_seq    INTEGER,   -- 이 달이 몇 번째 회차인지(1-based)
  installment_months INTEGER    -- 총 개월수 N. 화면엔 '할부 seq/months'
);

CREATE INDEX idx_tx_date ON transactions(date);
-- 휴지통 목록·자동정리(deleted_at 기준)를 위한 인덱스.
CREATE INDEX idx_tx_deleted ON transactions(deleted_at);
-- 할부 그룹 조회(한 번에 취소)를 위한 인덱스.
CREATE INDEX idx_tx_installment ON transactions(installment_id);

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

-- 정기 지출 규칙(관리비·구독료 등).
-- 예전엔 이 규칙이 각자 폰의 localStorage에만 있어서 부부 사이에 동기화되지 않았다.
-- 한쪽이 규칙을 지워도 다른 쪽 폰이 계속 등록해대서 "분명 지웠는데 또 생겨요"가 됐고,
-- 원인이 상대 폰에 있다는 걸 앱 화면만 봐서는 알 수 없었다.
CREATE TABLE recurring_rules (
  id         TEXT PRIMARY KEY,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  amount     INTEGER NOT NULL CHECK (amount > 0 AND amount < 100000000000),
  category   TEXT NOT NULL CHECK (length(category) BETWEEN 1 AND 40),
  day        INTEGER NOT NULL CHECK (day BETWEEN 1 AND 31)
);

-- "이 규칙을 이 달에 이미 등록했다"는 사실 자체를 남긴다. 거래가 아니라 '등록했음'을 기억하는 게 핵심.
-- 예전에는 이걸 기억하는 곳이 없어서, 자동 등록된 관리비를 지우면 바로 다음 loadData가
-- "어? 없네" 하고 즉시 다시 만들었다. 사용자는 삭제 자체를 할 수 없었는데 화면엔 '삭제 완료'가 떴다.
-- 거래를 지워도 이 기록은 남으므로 되살아나지 않는다.
-- PRIMARY KEY가 곧 잠금이라, 부부가 같은 순간에 앱을 열어도 INSERT OR IGNORE로 한 번만 등록된다.
CREATE TABLE recurring_applied (
  rule_id    TEXT NOT NULL,
  ym         TEXT NOT NULL CHECK (ym GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]'),
  tx_id      TEXT,
  applied_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (rule_id, ym)
);

-- 앱 설정(현재는 Gemini API 키와 자동 감지된 모델명).
-- 키를 여기 두는 이유: 앱 설정 화면에서 넣고 싶다는 요구가 있었는데, 예전처럼 localStorage에 두면
-- XSS 한 번에 털려 계정에 요금이 붙는다. 서버에 두면 앱에서 넣되 브라우저에는 남지 않는다.
-- (Worker secret 만큼 강하진 않지만 — secret은 별도 암호화 — Worker 인증을 통과해야만 닿고
--  키 값 자체는 브라우저로 절대 되돌려주지 않는다. localStorage와는 비교가 안 된다.)
CREATE TABLE app_settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 로그인 무차별 대입 방어. 비밀번호가 하나뿐이라 400ms 지연만으론 병렬 공격을 못 막는다.
-- IP별 최근 10분 시도 횟수를 세어 임계 초과 시 429. append-only라 병렬 요청에도 카운트가 안 샌다.
CREATE TABLE login_attempts (
  ip TEXT NOT NULL,
  at INTEGER NOT NULL
);
CREATE INDEX idx_login_at ON login_attempts(at);

-- 개인 계정. 예전엔 부부가 공유 비밀번호 하나(APP_PASSWORD)로 로그인했지만, 이제 각자 이름+비밀번호로
-- 계정을 만든다. 예전 공유 비밀번호는 '가입 코드'가 되어 계정을 만들 때만 쓴다. 가계부 데이터는 그대로 공유.
-- 비밀번호는 원문을 저장하지 않고 계정마다 무작위 salt로 PBKDF2-SHA256(150,000회) 해시만 담는다.
CREATE TABLE users (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 40),
  salt       TEXT NOT NULL,
  hash       TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 사용자 카테고리. 내장 카테고리는 앱(클라이언트)에 있고, 여기엔 사용자가 추가한 것만 담는다.
-- 거래의 category는 문자열이라, 카테고리를 지워도 기존 거래는 그 이름 그대로 남는다(앱이 📦로 그린다).
CREATE TABLE categories (
  id         TEXT PRIMARY KEY,
  type       TEXT NOT NULL CHECK (type IN ('income','expense')),
  name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 20),
  emoji      TEXT NOT NULL DEFAULT '🏷️' CHECK (length(emoji) <= 8),
  sort       INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(type, name)
);
