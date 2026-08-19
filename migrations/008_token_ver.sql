-- 토큰 무효화용 버전. 비밀번호를 바꾸거나 재설정하면 이 값을 +1 한다.
-- 발급된 토큰 payload에 이 값을 넣어두고, 인증 때 '토큰의 v == 계정의 현재 token_ver'인지 대조한다.
-- 그래서 비번을 바꾸면 그 이전에 발급된(=옛 v) 토큰이 전부 즉시 무효가 된다(다른 기기 강제 로그아웃).
--   - 적용: npx wrangler d1 execute gagyebu --local  --file=migrations/008_token_ver.sql
--          npx wrangler d1 execute gagyebu --remote --file=migrations/008_token_ver.sql   (배포 '전'에)
--   - 기존 토큰은 v가 없어 '0'으로 취급된다. 컬럼 기본값도 0이라, 배포해도 지금 로그인된 사람은 안 끊긴다.
ALTER TABLE users ADD COLUMN token_ver INTEGER NOT NULL DEFAULT 0;
