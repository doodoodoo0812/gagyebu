-- 007: 정기 '수입'도 자동등록 (급여 등)
-- 적용(로컬):  npx wrangler d1 execute gagyebu --local  --file=migrations/007_recurring_income.sql
-- 적용(운영):  npx wrangler d1 execute gagyebu --remote --file=migrations/007_recurring_income.sql
--
-- 지금까지 정기 규칙은 지출만 만들 수 있었다(자동등록이 'expense'로 박혀 있었다).
-- 급여처럼 매달 같은 날 들어오는 수입도 같은 방식으로 넣을 수 있게 type을 둔다.
-- 기본값 expense라 기존 규칙은 그대로 동작한다.
ALTER TABLE recurring_rules ADD COLUMN type TEXT NOT NULL DEFAULT 'expense';
