# 이어받는 사람에게 (개발 인수인계)

우리집 가계부 — 부부가 아이폰 홈화면에 설치해 쓰고 PC로도 여는 한국어 가계부 PWA.
Cloudflare Worker + D1. **운영 주소: https://gagyebu.mandoo0812.workers.dev**

## 0. 시작 전 이 순서로 파악할 것
1. `README.md` — 구조·설치·개발·비밀값·요금
2. `schema.sql` — DB 제약(날짜 검증·정기지출 중복방지)의 "왜"가 주석에 있음
3. `git log`(최근 ~15개) — 커밋 메시지에 "무엇을 왜 고쳤는지"가 길게 적혀 있음.
   2026-07-17에 Supabase→Cloudflare 이전 + 감사 3회로 버그 다수 수정 + UX 개편을 했다.

## 1. 실행 / 배포 (★ 코드만 보면 틀리기 쉬움)
```
npx wrangler dev --port 8790 --local      # 로컬. .dev.vars에 APP_PASSWORD/SESSION_SECRET (git 제외)
npx wrangler deploy                        # ★ 배포는 이 명령. git push 자동배포 아님(artclass와 다름)
npx wrangler d1 execute gagyebu --remote --file=schema.sql   # 스키마(새 DB 최초 1회)
```
- **스키마 변경은 `migrations/`의 파일을 순서대로 적용**(운영 DB는 이미 데이터가 있어 schema.sql 통짜 재실행 불가).
  `--local`로 먼저, 확인 후 `--remote`로. 예: `npx wrangler d1 execute gagyebu --remote --file=migrations/001_soft_delete.sql`.
  적용 순서는 배포보다 **먼저**(새 워커가 새 컬럼/테이블을 참조하므로). 001=deleted_at(소프트삭제), 002=categories(사용자 카테고리).
- 로컬 wrangler dev는 백그라운드 `&`로 띄우면 호출 사이에 죽는다 — **서버 기동과 curl 테스트를 한 번의 명령으로 묶을 것**(`nohup … & disown` 후 폴링→테스트).
- **Git Bash에서 `curl -d '{"name":"한글"}'` 처럼 한글을 인라인 인자로 넘기면 전송 전에 깨진다**(DB엔 U+FFFD가 저장된다).
  앱 버그로 오해하기 쉬우니, 한글이 든 요청은 **UTF-8 파일로 저장해 `--data-binary @파일`로 보낼 것**.
  (검증 완료: 파일로 보내면 워커+D1 왕복 후 코드포인트까지 동일. 앱 경로는 정상이다.)
- 배포 후 라이브는 `curl`로 배포본 해시=로컬 해시 폴링해 확인. 엣지 캐시로 1~2회는 옛 버전 나올 수 있음.
- `compatibility_date`는 설치된 wrangler의 로컬 런타임 상한(2026-05-01). 더 뒤로 올리면 `wrangler dev`가 안 뜸.

## 2. 비밀값 (값은 코드·저장소에 없음. Cloudflare secret에만)
| 이름 | 역할 | 바꾸면 |
|---|---|---|
| `APP_PASSWORD` | 부부 공유 로그인 비번 | 이미 로그인된 폰은 유지, 새 로그인만 새 비번 |
| `SESSION_SECRET` | 세션 토큰 서명키 | 모든 기기 즉시 로그아웃 |
| `GEMINI_API_KEY` | 영수증 AI(선택) | 앱 설정에서도 넣을 수 있음(서버 저장). 없으면 AI만 꺼짐 |

`npx wrangler secret put <이름>` 또는 대시보드. **APP_PASSWORD 분실 시 앱 진입 불가**(데이터는 D1에 남으니 새 비번으로 덮으면 됨).

## 3. 반드시 아는 함정 (코드를 아무리 봐도 안 보이는 것)
- **데모 모드로 테스트하면 클라우드 경로 버그가 안 보인다.** 실제 검증은 로그인해서 할 것. `useDemoMode()`로 로컬 시드.
- **서비스워커(sw.js)가 `/api/*`를 캐시하면 안 된다.** 캐시하면 저장은 되는데 목록이 옛 응답을 받아 "저장 완료"라 하고 화면엔 안 뜬다(한 번 겪음). 배포 시 `CACHE_NAME` 버전 올릴 것.
- **목록 응답에 `photo_url`(base64) 넣지 말 것** — 6개월치면 수십 MB. 목록엔 `has_photo`만, 이미지는 `/api/tx/:id/photo`로 따로.
- **`toISOString()` 쓰지 말 것** — UTC라 한국 자정~오전 9시엔 어제가 된다. `todayLocal()` 사용.
- **카테고리는 `CATEGORIES`에 있는 key만 유효** — 지출은 **'관리비'**(주거·통신 아님), 수입은 급여/부수입/용돈/기타수입. 없는 이름 쓰면 인식돼도 적용 안 돼 '실패'처럼 보임.
- **테마는 `document.body`의 `data-theme`** (documentElement 아님).
- **PC 레이아웃은 1920px에서 확인** — 1280px에선 안 드러나는 문제가 있다(FAB이 화면 끝으로 튀는 등).
- **Windows에서 `pkill` 안 먹는다.** 로컬 서버 끌 때: `powershell "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | ? { $_.CommandLine -like '*wrangler*dev*' } | % { Stop-Process -Id $_.ProcessId -Force }"` + `taskkill //F //IM workerd.exe`. **끄고 나서 포트로 죽었는지 꼭 확인**(TaskStop만으론 workerd가 고아로 남음).
- **자동화 브라우저 패널은 백그라운드라 IntersectionObserver 콜백이 안 온다.** 지연로드 등을 IO로 짜면 이 환경에선 안 뜬다(실기기엔 뜸). 핵심 기능을 IO에 맡기지 말 것.
- 스크린샷 툴은 패널 미표시 시 타임아웃 → JS로 상태를 읽어 검증.

## 4. 남은 일 (문서·코드에 없으니 여기 적음)
- **실기기(아이폰) 확인 아직 안 됨** — 전부 브라우저 에뮬레이션/로컬 로그인 curl로만 검증. 특히 최근 추가한
  **거래 검색**(목록 상단), **휴지통**(설정), **카테고리 관리**(설정), **JSON 백업/복원**(설정), **금액 콤마 입력**을 폰에서 확인 필요.
- **JSON 복원의 요청 크기** — 사진 많은 백업을 복원하면 POST 본문이 매우 커질 수 있다(수십 MB). 부부 몇 달치는 문제없지만,
  아주 큰 백업은 나눠 넣거나 서버에서 청크 처리가 필요할 수 있음(아직 대용량 복원은 실측 안 함).
- **Gemini 실제 인식은 실키로 끝까지 검증 못 함** — 로직·모델 자동감지·404 자가복구·설정 UI는 확인. 키 넣고 영수증 한 장 찍어봐야 품질 확인 가능.
- **카카오 로그인 — 안 하기로 결정(26-07-28).** 부부 2명이 하나의 가계부를 일부러 공유하는 구조라
  공유 비밀번호 → 서명 토큰이 오히려 최적(외부 의존성·콘솔 설정 없음, 90일이라 재로그인 드묾).
  예전에 장식이던 버튼을 KOE205까지 나서 제거한 이력도 있음. 되살릴 이유가 생기면(예: 사용자 여러 명·개별 권한)
  Worker `issueToken` 재사용으로 서버 토큰교환만 붙이면 됨.

## 5. 검증 습관 (이 저장소에서 지켜온 것)
- 고쳤다고 말하기 전에 **실제로 동작을 관찰**. 데모가 아니라 로그인 경로로.
- 커밋 메시지엔 **무엇을 왜** 고쳤는지 남긴다(다음 사람이 git log로 파악).
- 로컬 서버는 쓰고 나면 그 자리에서 끄고 **포트로 죽었는지 확인**.
