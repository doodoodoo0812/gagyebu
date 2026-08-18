-- 006: 금액이 매달 다른 정기지출 (관리비 등)
-- 적용(로컬):  npx wrangler d1 execute gagyebu --local  --file=migrations/006_recurring_variable.sql
-- 적용(운영):  npx wrangler d1 execute gagyebu --remote --file=migrations/006_recurring_variable.sql
--
-- variable=1 이면 날짜는 정해져 있지만 금액이 매달 달라서 자동으로 넣을 수 없다.
-- 그날이 되면 자동등록 대신 "금액을 입력하세요" 알림만 보내고, 사용자가 넣을 때 등록된다.
-- amount는 그런 규칙에선 '지난달 금액'(참고용 기본값)으로 쓴다.
ALTER TABLE recurring_rules ADD COLUMN variable INTEGER NOT NULL DEFAULT 0;
