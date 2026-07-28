-- 002: 사용자 카테고리 추가
-- 적용(로컬):  npx wrangler d1 execute gagyebu --local  --file=migrations/002_categories.sql
-- 적용(운영):  npx wrangler d1 execute gagyebu --remote --file=migrations/002_categories.sql
--
-- 내장 카테고리는 앱에 있고, 이 테이블엔 사용자가 추가한 것만 담는다.
-- 거래의 category는 문자열이라 카테고리를 지워도 기존 거래는 그대로 남는다(앱이 📦로 그린다).
CREATE TABLE IF NOT EXISTS categories (
  id         TEXT PRIMARY KEY,
  type       TEXT NOT NULL CHECK (type IN ('income','expense')),
  name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 20),
  emoji      TEXT NOT NULL DEFAULT '🏷️' CHECK (length(emoji) <= 8),
  sort       INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(type, name)
);
