# 💰 우리집 가계부 — 설치 & 사용 가이드

## 📱 아이폰에 앱으로 설치하는 방법

1. **Safari**로 앱 URL 열기 (Chrome, 카카오 브라우저 X)
2. 하단 공유 버튼(□↑) 탭
3. **"홈 화면에 추가"** 선택
4. 이름 확인 후 **추가** 탭
5. 홈 화면에 앱 아이콘이 생겨요! 🎉

---

## ☁️ Supabase 클라우드 설정 (부부 공유)

### 1단계: Supabase 프로젝트 만들기
1. [supabase.com](https://supabase.com) 무료 가입
2. **New Project** 클릭
3. 프로젝트 이름, 데이터베이스 비밀번호 설정
4. 지역: **Northeast Asia (Seoul)** 선택

### 2단계: 데이터베이스 테이블 만들기
1. 좌측 메뉴 **SQL Editor** 클릭
2. **New query** 클릭
3. 아래 SQL 전체 복사해서 붙여넣기:

```sql
-- 거래 테이블
CREATE TABLE transactions (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  created_at timestamptz DEFAULT now(),
  date date NOT NULL,
  type text NOT NULL CHECK (type IN ('income', 'expense')),
  category text NOT NULL,
  name text NOT NULL,
  amount integer NOT NULL CHECK (amount > 0),
  memo text,
  photo_url text,
  is_recurring boolean DEFAULT false,
  user_name text DEFAULT ''
);

ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all authenticated" ON transactions FOR ALL USING (true);

-- 예산 테이블
CREATE TABLE budgets (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  created_at timestamptz DEFAULT now(),
  month text NOT NULL,
  category text NOT NULL,
  amount integer NOT NULL CHECK (amount > 0),
  UNIQUE(month, category)
);

ALTER TABLE budgets ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all authenticated" ON budgets FOR ALL USING (true);
```

4. **RUN** 클릭

### 3단계: API 키 복사
1. 좌측 **Settings** → **API**
2. **Project URL** 복사
3. **anon public** 키 복사

### 4단계: 앱에서 연결
1. 앱 실행 후 설정 화면에서 URL, Key 입력
2. 내 이름 입력 (남편/아내 등)
3. **연결하기** 탭!

### 5단계: 와이프 폰에도 설치
- 같은 URL, Key 입력하면 데이터 자동 공유돼요! 🎉

---

## 🔒 보안에 대해

- **데이터는 Supabase(한국 서버)에 암호화 저장**됩니다
- URL과 Key를 가진 사람만 접근 가능해요
- 더 강한 보안이 필요하면 Supabase에서 비밀번호 인증 추가 가능

---

## 📲 호스팅 방법 (인터넷 어디서나 접근)

### 옵션 1: Vercel (추천, 무료)
1. [vercel.com](https://vercel.com) 가입
2. 파일 3개(index.html, manifest.json, sw.js) 업로드
3. 자동으로 HTTPS URL 발급!

### 옵션 2: Netlify (무료)
1. [netlify.com](https://netlify.com) 가입
2. 파일 드래그 앤 드롭
3. URL 발급 완료!

### 옵션 3: GitHub Pages (무료)
1. GitHub 저장소 만들기
2. 파일 업로드
3. Settings → Pages → 배포

---

## 📊 기능 목록

| 기능 | 설명 |
|------|------|
| 거래 추가 | 지출/수입 빠르게 입력 |
| 영수증 AI 인식 | 사진 찍으면 금액/가게명 자동 입력 |
| 카테고리 | 식비, 카페, 교통, 마트, 관리비 등 12개 |
| 예산 관리 | 카테고리별 예산 설정 및 초과 알림 |
| 정기 지출 | 매월 자동 등록 (관리비, 구독료 등) |
| 그래프 | 도넛, 막대, 꺾은선 차트 |
| 월별 비교 | 전월 대비 증감 표시 |
| 부부 공유 | Supabase 실시간 동기화 |
| Excel 내보내기 | 월별/전체 .xlsx 다운로드 |
| 5가지 테마 | 네이비, 다크골드, 화이트, 포레스트, 로즈 |
| PWA | 아이폰 홈 화면에 앱으로 설치 |

---

## ❓ AI 영수증 인식이 안 되는 경우

AI 인식 기능은 Anthropic API를 사용해요.
앱 내부에 API 키가 없는 경우 인식이 안 될 수 있어요.
이 경우 사진만 첨부하고 수동으로 입력하면 됩니다.

---

Made with ❤️ — 우리집 맞춤 가계부
