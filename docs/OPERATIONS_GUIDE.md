# 운영·업데이트 설명서

## 1. 빌드 및 배포

### 로컬 빌드

```bash
export JAVA_HOME=<JDK 17>
export ANDROID_HOME=<Android SDK (platform 35, build-tools 35.0.0)>

./gradlew testDebugUnitTest      # 단위 테스트
./gradlew lintDebug              # 정적 분석
./gradlew assembleDebug          # app/build/outputs/apk/debug/app-debug.apk
./gradlew assembleRelease        # app/build/outputs/apk/release/app-release.apk
./gradlew bundleRelease          # app/build/outputs/bundle/release/app-release.aab
```

### 릴리스 서명

`local.properties` 또는 환경변수로 키를 지정합니다.

```properties
releaseStoreFile=/secure/eum-release.jks
releaseStorePassword=****
releaseKeyAlias=eum
releaseKeyPassword=****
```

지정하지 않으면 디버그 키로 서명되어 "설치 가능한" 산출물이 만들어집니다(스토어 업로드 불가).

### CI

`.github/workflows/android-ci.yml` — JDK 17, SDK 35 설치 후 테스트→lint→APK/AAB 빌드→
SHA-256 생성→아티팩트 업로드. 서명 키는 `RELEASE_STORE_BASE64`,
`RELEASE_STORE_PASSWORD`, `RELEASE_KEY_ALIAS`, `RELEASE_KEY_PASSWORD` 시크릿으로 주입합니다.
시크릿이 없으면 서명 없이 빌드만 수행합니다.

> GitHub App 토큰에는 `.github/workflows/` 푸시 권한이 없어, 저장소에는 워크플로 파일을
> 제외한 커밋이 올라갑니다. 로컬에는 파일이 유지되며, 필요하면 저장소 관리자가 직접
> 추가하거나 GitHub 웹 UI 로 작성해야 합니다.

## 2. 앱 사용 흐름

1. 설치 → 홈 화면
2. "광고 차단" 스위치 → Android VPN 동의 → VPN 연결(포그라운드 알림 표시)
3. 필요 시 "15분 중지", 필터 목록 on/off, 특정 도메인 허용/차단
4. "악성코드 검사" → 빠른 검사 / 설치 앱 검사 / APK 선택
5. 결과 화면에서 위험 등급·근거·권장 조치 확인, 앱 정보/삭제 화면 이동, 오탐 신고
6. "보안 DB" 에서 필터/해시/패턴 규칙 버전과 수동 업데이트

## 3. 보안 DB 및 필터 업데이트

자세한 채널 구성은 `docs/UPDATE_GUIDE.md` 참고.

- 주기: 하루 1회(WorkManager, 네트워크 연결 시), 앱 시작 시 예약 보장
- 수동: 보안 DB 화면의 "지금 업데이트"/항목별 버튼
- 검증: Ed25519 서명 → SHA-256 → 버전 단조 증가
- 실패 시 기존 데이터 유지, `update_history` 에 사유 기록
- 테스트 데이터는 `isTestData = true` 로 저장되어 UI 에 "예시 데이터" 배지가 표시됩니다.

## 4. 로그/데이터 보관

- `blocked_dns_events`: 설정된 보관 기간(기본 30일) 지난 행 자동 삭제(VPN 시작 시)
- `scan_sessions`: 사용자가 삭제하거나 `deleteSessionsOlderThan` 정책으로 정리 가능
- 민감 정보(도메인/패키지)는 기기 내부 DB 에만 저장

## 5. 장애 대응

| 증상 | 확인 |
| --- | --- |
| VPN 이 켜지지 않음 | 다른 VPN 앱이 활성인지, VPN 동의가 철회되지 않았는지 확인 |
| 인터넷이 안 됨 | VPN 은 DNS 만 라우팅하므로 일반 통신은 영향이 없어야 함. 업스트림(시스템 DNS) 상태 확인, DoH/DoT 전환 시도 |
| 특정 앱이 동작하지 않음 | 최근 차단 기록에서 해당 도메인을 "허용" 처리 또는 앱별 예외 등록 |
| 검사 결과가 "검사 불가" | APK 파일 접근 제한(메타데이터만 검사) 또는 ZIP 손상 여부 확인 |
| 업데이트 실패 | 보안 DB 화면 이력에서 `REJECTED_INTEGRITY`(서명/해시) / `REJECTED_ROLLBACK`(버전) 확인 |

## 6. 배포 전 체크리스트

- [ ] `docs/PLAY_STORE_SUBMISSION.md` 의 VPN·QUERY_ALL_PACKAGES 신고 문구 입력
- [ ] 개인정보 처리방침의 문의 이메일을 실제 주소로 교체(`support_email` 문자열, 문서)
- [ ] 릴리스 서명 키 등록 및 백업
- [ ] 실기기 테스트: Android 10/12/14 에서 VPN 연결·DNS 차단·정상 인터넷 유지
- [ ] DoH/DoT 실제 통신 확인
- [ ] 스토어 스크린샷·아이콘·대표 이미지 준비
- [ ] 내부 테스트 트랙 업로드 후 ANR/크래시 확인
