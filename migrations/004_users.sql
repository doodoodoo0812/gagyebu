-- 개인 계정. 예전엔 부부가 공유 비밀번호 하나(APP_PASSWORD)로 로그인했다.
-- 이제 각자 '이름 + 자기 비밀번호'로 계정을 만들고, 예전 공유 비밀번호는 '가입 코드'가 된다
-- (계정을 만들 때 한 번만 필요). 로그인·비밀번호 변경은 본인이 하고, 가계부 데이터는 그대로 공유한다.
--
-- 비밀번호는 원문을 저장하지 않는다. 계정마다 무작위 salt를 만들고 PBKDF2-SHA256(150,000회)로
-- 해시만 저장한다. 로그인 때 같은 salt로 다시 해시해 상수시간 비교(safeEqual)로 맞춰본다.
CREATE TABLE IF NOT EXISTS users (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 40),
  salt       TEXT NOT NULL,   -- 16바이트 무작위값의 hex
  hash       TEXT NOT NULL,   -- PBKDF2 파생 256비트의 hex
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
