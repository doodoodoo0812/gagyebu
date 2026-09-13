-- 009: 🏢 사무실 지출 연동 (가계부 → 동래연제앱)
-- 적용(로컬):  npx wrangler d1 execute gagyebu --local  --file=migrations/009_office.sql
-- 적용(운영):  npx wrangler d1 execute gagyebu --remote --file=migrations/009_office.sql
--
-- 지출을 넣을 때 [🏢 사무실용]으로 찍으면 가계부에는 그대로 남으면서
-- 동래연제앱 💸 지출 탭에도 자동으로 들어간다. 작업서: 0.app/_문서/가계부_사무실지출_연동_작업서.md
--
-- office_dest : NULL이면 우리집 살림. 'artclass'면 동래연제.
--               0/1 플래그가 아니라 '보낼 곳'으로 둔 이유 — 사업체가 둘(홍선생미술 + 맘편한 심리상담센터)이라
--               나중에 센터가 붙어도 목적지만 늘리면 되고 코드를 뒤집을 일이 없다. 지금 드는 수고는 사실상 0.
-- office_cat  : 저쪽(동래연제) 분류 원문 그대로. '운영비|비품·소모품' 형태로 담는다.
-- office_sync : NULL(보낼 것 없음) / 'pending' / 'done' / 'failed:<사유>'
--               저쪽이 죽어 있어도 **가계부 저장은 무조건 성공**시키고 여기에만 남긴다. 10분 크론이 다시 보낸다.
-- office_doc  : 저쪽 Firestore 문서 id. 수정·삭제를 따라가려면 있어야 한다.
ALTER TABLE transactions ADD COLUMN office_dest TEXT;
ALTER TABLE transactions ADD COLUMN office_cat  TEXT;
ALTER TABLE transactions ADD COLUMN office_sync TEXT;
ALTER TABLE transactions ADD COLUMN office_doc  TEXT;
-- 못 보낸 건을 찾는 조회(재시도 크론·설정 화면의 "아직 못 보낸 N건")를 위한 인덱스.
CREATE INDEX IF NOT EXISTS idx_tx_office ON transactions(office_dest, office_sync);
