-- 005: 웹푸시 구독 (앱이 꺼져 있어도 알림)
-- 적용(로컬):  npx wrangler d1 execute gagyebu --local  --file=migrations/005_push.sql
-- 적용(운영):  npx wrangler d1 execute gagyebu --remote --file=migrations/005_push.sql
--
-- 브라우저가 만들어준 구독 정보를 그대로 담는다. endpoint가 곧 그 기기의 주소라 PRIMARY KEY로 쓴다
-- (같은 기기에서 다시 구독하면 덮어쓰기). 기기마다 한 줄이므로 부부가 폰·PC를 여러 대 써도 된다.
-- 푸시가 410/404로 돌아오면 그 구독은 죽은 것이라 서버가 알아서 지운다.
CREATE TABLE IF NOT EXISTS push_subscriptions (
  endpoint   TEXT PRIMARY KEY,
  p256dh     TEXT NOT NULL,
  auth       TEXT NOT NULL,
  user_name  TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
