# 서명된 업데이트 채널 운영 가이드

EUM SECURITY PRO 의 필터/해시/패턴 DB 는 **서명된 매니페스트**로만 교체됩니다.

## 1. 파일 배치

```
<base>/ad-filter/manifest.json      <base>/ad-filter/data-<version>.json
<base>/threat-hash/manifest.json    <base>/threat-hash/data-<version>.json
<base>/yara-rules/manifest.json     <base>/yara-rules/data-<version>.json
```

HTTPS 로만 제공해야 하며(HTTP 는 코드에서 거부), 리다이렉트도 HTTPS 만 허용됩니다.

## 2. 매니페스트 형식

```json
{
  "manifest": {
    "target": "THREAT_HASH",
    "version": 12,
    "versionLabel": "2026.11.22",
    "publishedAt": 1795276800000,
    "payloadUrl": "https://cdn.example.com/threat-hash/data-12.json",
    "payloadSha256": "<64 hex>",
    "payloadSize": 12345,
    "entryCount": 340,
    "isTestData": false
  },
  "signature": "<base64 Ed25519 signature>"
}
```

- 서명 대상: `manifest` 객체의 **canonical JSON**(필드 순서 고정, 공백 없음).
  - 순서: `target, version, versionLabel, publishedAt, payloadUrl, payloadSha256, payloadSize, entryCount, isTestData`
  - `UpdateManifestCodec.canonicalBytes()` 와 동일한 문자열이어야 합니다.
- 서명: Ed25519, 64바이트, base64.
- `version` 은 **단조 증가**해야 합니다(현재 버전 이하는 거부).

## 3. 페이로드 형식

### 해시(THREAT_HASH)
```json
[{"sha256":"<64hex>","threatName":"Android.Trojan.X","family":"X","category":"malware",
  "severity":"HIGH","confidence":90,"source":"EUM","firstSeen":1795000000000,"lastSeen":1795200000000}]
```

### 패턴(YARA_RULES)
```json
{"engine":"YARA_SUBSET","rules":[{"name":"EUM_Foo","category":"suspicious_pattern",
  "severity":"MEDIUM","content":"rule EUM_Foo { strings: $a = \"bad\" condition: $a }",
  "source":"EUM","version":"2026.11.1"}]}
```

### 필터(AD_FILTER)
```json
{"source":"EUM Ads","category":"ADS","license":"MIT","rules":["||ads.example.com^","@@||ok.example.com^"]}
```

페이로드는 gzip(`1f 8b`)도 허용합니다. gzip 인 경우 `payloadSha256`/`payloadSize` 는 **압축된
바이트** 기준입니다.

## 4. 앱에 채널 연결

`gradle.properties`(또는 빌드 인자):

```properties
updateBaseUrl=https://cdn.example.com/eum
updatePublicKey=<64 hex Ed25519 공개키>
```

`BuildConfig.UPDATE_BASE_URL` / `UPDATE_PUBLIC_KEY` 로 주입됩니다. 값이 비어 있으면 앱은
"업데이트 채널이 설정되지 않았습니다" 상태로 동작하고 탐지는 내장 데이터만 사용합니다.

## 5. 키 관리

- 개인키는 절대 저장소에 커밋하지 않습니다(CI 시크릿/HSM).
- 키 교체 시 앱 업데이트로 새 공개키를 배포해야 합니다(매니페스트 다중 서명 미지원).
- 테스트 채널은 `isTestData: true` 로 발행해 UI 에 "예시 데이터" 배지가 붙게 합니다.

## 6. 발행 절차(예시 스크립트)

```bash
# 1) 페이로드 작성 및 해시 계산
sha256sum data-12.json
# 2) canonical JSON 작성 후 Ed25519 서명(base64)
#    UpdateManifestCodec.canonicalBytes() 와 동일한 문자열을 사용
# 3) manifest.json 업로드 → 앱에서 "지금 업데이트"
```

## 7. 실패 처리

| 상황 | 앱 동작 |
| --- | --- |
| 서명 불일치 | 업데이트 거부, 기존 데이터 유지, 이력 `REJECTED_INTEGRITY` |
| SHA-256 불일치/크기 불일치 | 상동 |
| 버전 ≤ 현재 | 거부, `REJECTED_ROLLBACK` |
| 레코드 수 ≠ entryCount | 거부(`MALFORMED`), 기존 데이터 유지 |
| 네트워크 오류 | 이력 `FAILED`, 최대 2회 재시도(WorkManager) |
