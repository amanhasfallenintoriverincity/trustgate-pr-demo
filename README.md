# TrustGate PR Bot Demo Target

합성 데이터만 사용하는 공개 데모용 Python HTTP API입니다. 실제 개인정보·자격 증명이 없습니다.

- `POST /api/login` — 세션 발급
- `GET /api/admin/data` — 관리자 보호 자원
- `GET /api/download?file=guide.txt` — 문서 조회

계정은 `alice`(일반), `admin`(관리자)이며 비밀번호는 소스에 공개된 DEMO 문자열입니다.
문서 `guide.txt`와 `private/canary.txt`는 실행 시 생성되는 합성 파일입니다.

## 테스트

```bash
python3 -B tests.py
```

## 변경 이력

- 2026-11: PR 봇 검증용 데모 변경

<!-- lab ingress verification -->
