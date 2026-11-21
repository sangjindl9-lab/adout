# 테스트 및 빌드 결과 (실행 기록)

실행 환경
- OS: Linux (x86_64), 컨테이너
- JDK: Temurin 17.0.21.1+2
- Android SDK: platform 35, build-tools 35.0.0
- Gradle 8.9 (wrapper), AGP 8.7.3, Kotlin 2.0.21

## 1. 단위 테스트 — `./gradlew testDebugUnitTest`

결과: **BUILD SUCCESSFUL**, **79 tests, 0 failures**

| 테스트 클래스 | 건수 | 검증 내용 |
| --- | --- | --- |
| `DnsWireTest` | 8 | DNS 질의 파싱, 압축 포인터, NXDOMAIN/0.0.0.0 응답, TTL 계산, 손상 입력, ID 재작성 |
| `DnsFilterTest` | 11 | hosts·AdGuard 규칙 파서, 서브도메인 매칭, 사용자 허용/차단 우선순위, 예외 규칙, `$dnstype`, 공용 접미사 보호, 와일드카드, punycode, 응답 캐시 TTL |
| `DnsTunHandlerTest` | 8 | UDP/53 차단·허용, IPv4/IPv6 응답 재포장, 업스트림 실패(SERVFAIL), 비DNS 폐기, 캐시 히트, 차단 스위치 |
| `IpPacketsTest` | 6 | IPv4/IPv6 UDP 생성·파싱, 헤더/UDP 체크섬, TCP·단편화 거부, 잘린 패킷 |
| `YaraEngineTest` | 9 | 내장 규칙 10종 컴파일, 매칭/불일치, hex 와일드카드, `N of them`, wide, nocase, 미지원(정규식) 보고, 2MB 버퍼 성능 |
| `ApkAnalyzerTest` | 10 | aapt2로 만든 실제 APK 픽스처의 AXML 매니페스트/권한/컴포넌트 파싱, v2/v3 서명 인증서 SHA-256, 파일 SHA-256, 위험 APK 판정, 손상 APK, 압축 폭탄, ZIP 경로 이탈, DEX 패턴 탐지 |
| `RiskAssessorTest` | 10 | 4단계 판정(위험/주의/미발견/불가), 점수 상한, SMS+인터넷 등 권한 조합, 신뢰 앱 완화, exported 컴포넌트 |
| `UpdateVerifierTest` | 7 | Ed25519 정상 서명, 본문 변조, 다른 키, 공개키 미설정, SHA-256/크기 불일치, 롤백 차단, HTTP URL 거부 |
| `UpdateClientTest` | 8 | 서명된 해시/규칙/필터 업데이트 적용, 페이로드 변조 시 기존 데이터 유지, 서명 오류, 다운그레이드 거부, 설정 없음, HTTP 오류 |
| `MigrationTest` | 2 | exported schema(v1) DDL 로 실제 v1 DB 생성 → v2 마이그레이션 후 Room 스키마 검증·데이터 보존·신규 컬럼 사용, 16개 테이블 존재 |

수치 근거: `app/build/test-results/testDebugUnitTest/*.xml`

## 2. 정적 분석 — `./gradlew lintDebug`

- 결과: **BUILD SUCCESSFUL**
- **0 errors, 123 warnings** (`app/build/reports/lint-results-debug.txt`)
- 경고는 대부분 미사용 리소스/번역 누락/버전 제안 수준이며 빌드를 막지 않습니다.

## 3. 빌드 산출물

| 산출물 | 경로 | 크기 | SHA-256 |
| --- | --- | --- | --- |
| Debug APK | `app/build/outputs/apk/debug/app-debug.apk` | 31,695,514 bytes | `5db2ffd7ec76815dc2ba27c614feeecb5b9666b0a77ffc34e27d867ad01cc609` |
| Release APK | `app/build/outputs/apk/release/app-release.apk` | 3,851,510 bytes | `b212b280e6ac403d478d2d15b8c02e8b5480240632b1ac1fa8a3df5460808a26` |
| Release AAB | `app/build/outputs/bundle/release/app-release.aab` | 4,427,510 bytes | `1e26da0c0920a24f16834e60a4262830b9d9a6ccd070f083db22544ef931655e` |

`/workspace/downloads/` 에 동일 파일 복사:
`eum-security-pro-debug.apk`, `eum-security-pro-release.apk`, `eum-security-pro-release.aab`

### 산출물 검증 (aapt2 / apksigner)

```
package: name='kr.eumsoft.securitypro' versionCode='1' versionName='1.0.0'
minSdkVersion:'29'  targetSdkVersion:'35'
uses-permission: INTERNET, ACCESS_NETWORK_STATE, FOREGROUND_SERVICE,
                 FOREGROUND_SERVICE_SPECIAL_USE, POST_NOTIFICATIONS,
                 QUERY_ALL_PACKAGES, WAKE_LOCK
Signer #1 certificate SHA-256: dc45cfba13f65d3a378e751fbbdce8eb12eeb9ab55df39fb3a1f7c60fdf642da
```

- `apksigner verify` 통과(v1+v2+v3 서명).
- 릴리스 키를 지정하지 않아 **디버그 키로 서명**되었습니다(스토어 업로드 전 `releaseStoreFile` 설정 필요).
- release 빌드는 R8 minify + 리소스 축소가 적용됩니다(3.85MB).

## 4. 수행하지 못한 테스트

- 실기기/에뮬레이터 계측 테스트(androidTest): 기기 없음 → 미수행
- 실기기 VPN 연결·DNS 차단·정상 인터넷 유지: 미수행
- DoH/DoT 실서버 왕복: 미수행
- 성능(시작 시간·DNS 지연·배터리): 미수행

자세한 내용은 `docs/KNOWN_LIMITATIONS.md` 참조.
