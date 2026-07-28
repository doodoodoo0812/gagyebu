-- 001: 소프트 삭제(휴지통) 도입
-- 적용(로컬):  npx wrangler d1 execute gagyebu --local  --file=migrations/001_soft_delete.sql
-- 적용(운영):  npx wrangler d1 execute gagyebu --remote --file=migrations/001_soft_delete.sql
--
-- ALTER ADD COLUMN / CREATE INDEX IF NOT EXISTS 는 기존 행을 건드리지 않는다(전부 deleted_at=NULL로 남음).
-- 여러 번 실행해도 안전하도록: 이미 컬럼이 있으면 ALTER는 오류가 나므로, 처음 한 번만 실행할 것.

ALTER TABLE transactions ADD COLUMN deleted_at TEXT;
CREATE INDEX IF NOT EXISTS idx_tx_deleted ON transactions(deleted_at);
