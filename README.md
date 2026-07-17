# 💰 우리집 가계부

부부가 함께 쓰는 가계부. Cloudflare Worker + D1.

**주소: https://gagyebu.mandoo0812.workers.dev**

> 옛 주소(`doodoodoo0812.github.io/gagyebu`)는 이사 안내 페이지만 띄운다.
> 2026-07-17에 Supabase → Cloudflare로 옮겼다. Supabase 무료 플랜이 7일만 안 써도 정지되고
> 90일이 지나면 복구조차 거부해서 실제로 프로젝트를 잃었기 때문이다. D1은 정지가 없다.

---

## 📱 폰에 설치

1. **Safari**로 위 주소 열기 (Chrome·카카오 브라우저는 설치가 안 된다)
2. 하단 공유 버튼(□↑) → **홈 화면에 추가**
3. 앱을 열고 **비밀번호**를 넣으면 끝. 부부가 같은 비밀번호를 쓰면 자동으로 공유된다.

둘러보기만 하려면 로그인 화면의 **⚡ 데모 모드로 시작** — 이 기기에만 저장되고 공유되지 않는다.

---

## 🗂 구조

```
_worker.js      Worker: / 앱 서빙 + /api/* 데이터 창구 (인증·D1·AI 전부 여기)
wrangler.toml   name=gagyebu, [assets] directory=./public, D1 바인딩 DB
schema.sql      D1 스키마
index.html      옛 GitHub Pages 주소용 이사 안내 (배포엔 미포함)
public/         ← 이 폴더만 공개된다
  index.html    앱 본체 (단일 파일)
  manifest.json
  sw.js
  icons/
```

브라우저에는 DB 키가 없다. 로그인하면 Worker가 서명한 세션 토큰(90일)만 받는다.
예전에는 브라우저가 Supabase를 직접 부르고 anon key가 화면 소스에 노출된 채 RLS는 "전부 허용"이라,
주소와 키만 알면 누구나 부부 가계부를 읽고 쓸 수 있었다.

---

## 🔧 개발

```bash
npx wrangler dev --port 8790 --local     # 로컬 (.dev.vars에 비밀값, git 제외됨)
npx wrangler deploy                      # 배포
npx wrangler d1 execute gagyebu --remote --file=schema.sql   # 스키마 적용
```

`compatibility_date`는 설치된 wrangler의 로컬 런타임 상한에 맞춰야 한다. 더 뒤로 잡으면 `wrangler dev`가 안 뜬다.

### 함정
- **서비스워커가 `/api/*`를 캐시하면 안 된다.** 캐시하면 거래를 저장해도 서버엔 들어가는데 목록은
  옛 응답을 받아 "저장 완료"라 해놓고 화면에 안 나타난다. (한 번 겪었다)
- **목록 응답에 `photo_url`을 넣지 말 것.** base64라 6개월치면 수십 MB가 된다.
  목록엔 `has_photo`만, 이미지는 `/api/tx/:id/photo`로 따로.
- **`toISOString()` 금지.** UTC라 한국 자정~오전 9시엔 어제가 된다. `todayLocal()` 사용.
- 카테고리는 `CATEGORIES`에 실제로 있는 key만 유효(지출은 '주거'가 아니라 **'관리비'**).
- 데모 모드는 로컬 저장이라 **클라우드 경로의 버그가 안 보인다.** 검증은 로그인해서 할 것.
- PC 레이아웃은 **1920px에서 확인**할 것. 1280px에선 안 드러나는 문제가 있다.

---

## 🔑 비밀값 (Cloudflare secret)

```bash
npx wrangler secret put APP_PASSWORD     # 부부 공유 로그인 비밀번호
npx wrangler secret put SESSION_SECRET   # 세션 토큰 서명키 (아무 긴 랜덤 문자열)
npx wrangler secret put GEMINI_API_KEY   # (선택) 영수증 AI 인식
```

| 바꾸면 | 결과 |
|---|---|
| `APP_PASSWORD` | 새로 로그인할 때만 새 비번 필요. **이미 로그인된 폰은 유지된다** |
| `SESSION_SECRET` | **모든 기기 즉시 로그아웃.** 비번이 샜을 땐 이것도 같이 바꿔야 쫓아낼 수 있다 |
| `GEMINI_API_KEY` | 없으면 AI 인식만 꺼진다(사진 저장·나머지 기능은 정상) |

`APP_PASSWORD`를 잊으면 앱에 못 들어간다. 데이터는 D1에 남아있으니 새 비번으로 덮어쓰면 된다.

---

## 📊 기능

| 기능 | 설명 |
|---|---|
| 거래 추가 | 지출/수입, 사진 첨부, 메모 |
| 문자 자동인식 | 카드 결제 문자를 붙여넣으면 금액·가게명·날짜·카테고리 자동 입력 |
| 영수증 AI | 사진을 찍으면 Gemini가 금액·가게명 인식 (`GEMINI_API_KEY` 필요) |
| 예산 | 카테고리별 월 예산, 초과 경고 |
| 정기 지출 | 매월 자동 등록. 규칙은 서버에 있어 부부가 공유한다 |
| 통계 | 도넛·6개월 추이·일별 차트, 월간 리포트, AI 소비 분석 |
| 달력 | 날짜별 지출 |
| Excel | 월별 / 전체 내보내기 |
| 테마 | 5종 |
| PWA | 홈 화면 설치, 오프라인 조회 |

---

## 💵 요금

**무료다.** Cloudflare 무료 플랜은 한도를 넘겨도 **청구되지 않고 그냥 멈춘다**
(D1 문서: "will not be able to run queries"). Firebase처럼 깜짝 청구서가 나올 수 없다.

부부 2명 실사용 추정: Workers 요청 **0.06%**, D1 읽기 **0.29%**, 쓰기 **0.02%**, 저장 연 141MB(**2.75%**).
사진 40장/월이면 5GB를 채우는 데 **약 36년**.

앱을 켜두기만 하면 서버 요청이 **0**이다(주기 타이머는 시계만 보고 알림을 띄울 뿐 서버를 부르지 않는다).
정기지출 자동등록도 이미 등록한 달이면 쓰기가 0이다(`INSERT OR IGNORE` 충돌 → `rows_written: 0`, 측정 확인).
