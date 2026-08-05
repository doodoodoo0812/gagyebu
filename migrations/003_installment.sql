-- 003: 카드사 + 무이자 할부
-- 적용(로컬):  npx wrangler d1 execute gagyebu --local  --file=migrations/003_installment.sql
-- 적용(운영):  npx wrangler d1 execute gagyebu --remote --file=migrations/003_installment.sql
--
-- card              : 카드사(선택). 일시불에도 기록 가능.
-- installment_id    : 같은 할부 N개월을 묶는 그룹 키(NULL이면 할부 아님).
-- installment_seq   : 이 달이 몇 번째 회차인지(1-based).
-- installment_months: 총 할부 개월수 N. 화면엔 '할부 seq/months'로 표시.
-- 할부는 등록 때 N개월치 거래를 각 달에 미리 만들어 둔다(같은 installment_id로 묶여 한 번에 취소 가능).
ALTER TABLE transactions ADD COLUMN card TEXT;
ALTER TABLE transactions ADD COLUMN installment_id TEXT;
ALTER TABLE transactions ADD COLUMN installment_seq INTEGER;
ALTER TABLE transactions ADD COLUMN installment_months INTEGER;
CREATE INDEX IF NOT EXISTS idx_tx_installment ON transactions(installment_id);
