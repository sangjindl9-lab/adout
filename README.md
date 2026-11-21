# EUM SECURITY PRO

Android 광고 차단·악성코드 검사 통합 보안 애플리케이션 (Kotlin / Jetpack Compose).

- **패키지**: `kr.eumsoft.securitypro`
- **minSdk 29 (Android 10) / targetSdk 35 / compileSdk 35**
- **아키텍처**: Clean Architecture(MVVM) + Hilt + Coroutines/Flow + Room + DataStore + WorkManager

## 핵심 엔진

| 구성 | 구현 |
| --- | --- |
| 광고 차단 | `VpnService` + 순수 Kotlin TUN DNS 처리기(IPv4/IPv6 UDP·53) + AdGuard/hosts 규칙 엔진 + DoH/DoT 업스트림 + 응답 캐시 |
| 악성코드 검사 | SHA-256 해시 대조, APK 정적 분석(AXML 매니페스트·서명 v2/v3·ZIP 안전 순회), YARA 부분집합 패턴 엔진, 권한 조합 분석, 4단계 위험 판정 |
| 자동 업데이트 | WorkManager(일 1회) + HTTPS + SHA-256 + Ed25519 서명 + 원자적 DB 교체 + 롤백 차단 |

UI는 6개 화면(홈/광고 차단/악성코드 검사/검사 결과/보안 DB/설정)이며, 한국어·영어·일본어·중국어(간체)·스페인어 리소스를 포함합니다.

## 빌드

```bash
./gradlew testDebugUnitTest   # 단위 테스트 (Robolectric 포함)
./gradlew lintDebug
./gradlew assembleDebug
./gradlew assembleRelease
./gradlew bundleRelease
```

필요 환경: JDK 17, Android SDK platform 35, build-tools 35.0.0.

## 문서

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — 구조와 데이터 흐름
- [docs/TEST_REPORT.md](docs/TEST_REPORT.md) — 실제 테스트/빌드 결과
- [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) — 알려진 제한과 미구현 기능
- [docs/OPERATIONS_GUIDE.md](docs/OPERATIONS_GUIDE.md) — 운영·업데이트 설명서
- [docs/PLAY_STORE_SUBMISSION.md](docs/PLAY_STORE_SUBMISSION.md) — Play 등록 자료(VPN·QUERY_ALL_PACKAGES 신고)
- [docs/PRIVACY_POLICY.md](docs/PRIVACY_POLICY.md) — 개인정보 처리방침 초안
- [docs/THIRD_PARTY_LICENSES.md](docs/THIRD_PARTY_LICENSES.md) — 오픈소스 라이선스
- [docs/UPDATE_GUIDE.md](docs/UPDATE_GUIDE.md) — 서명된 업데이트 채널 운영 방법

## 면책

이 앱은 알려진 위협 정보와 휴리스틱 근거를 제시할 뿐, "100% 안전"을 보장하지 않습니다.
DNS 차단은 앱 내부 광고나 HTTPS 영상 광고를 제거하지 못합니다.
