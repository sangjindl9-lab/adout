# 아키텍처

## 레이어

```
core/            Android 비의존 순수 Kotlin 엔진 (단위 테스트 대상)
  dns/           DNS 와이어 포맷, AdGuard/hosts 규칙 파서, 필터 엔진
  net/           IP/UDP 패킷 생성·파싱, TUN DNS 핸들러, 응답 캐시, 업스트림 인터페이스
  apk/           AXML 파서, ZIP 안전 리더, v1/v2/v3 서명 리더, 정적 분석기
  yara/          YARA 부분집합 컴파일러/매처, 내장 규칙
  pattern/       DEX/SO/스크립트 패턴 스캐너
  risk/          위험 판정(4단계), 권한 조합 분석
  crypto/        SHA-256
data/
  db/            Room 16 테이블, DAO, 마이그레이션, 관계 모델
  prefs/         DataStore 설정
  repo/          필터 저장소(런타임 스냅샷 관리)
  updater/       매니페스트 코덱, Ed25519 검증, HTTPS 페처, 업데이트 적용
scanner/         설치 앱 수집(PackageManager), 검사 오케스트레이터
service/         VpnService, DNS 업스트림(시스템/DoH/DoT), 알림, 상태 홀더
worker/          WorkManager 주기 작업(업데이트/자동 검사)
ui/              Compose 화면, ViewModel, 테마
```

## 광고 차단 데이터 흐름

```
앱/시스템 DNS 질의
   → VpnService TUN (가상 DNS 10.111.222.2, DNS 로만 라우팅)
   → DnsTunHandler: IP/UDP 파싱 → DNS 질의 파싱
   → DnsFilterEngine (사용자 허용 → 사용자 차단 → 예외 규칙 → 차단 규칙)
        ├─ 차단: NXDOMAIN 또는 0.0.0.0 응답 패킷 생성 → TUN 기록
        └─ 허용: 캐시 → 업스트림(시스템 DNS / DoH / DoT, protect() 적용)
                 → 응답 패킷 재포장 → TUN 기록
```

- VPN 은 **DNS 트래픽만** 라우팅합니다(0.0.0.0/0 미사용). 일반 인터넷 트래픽은 터널을 지나지 않습니다.
- 주요 공용 리졸버(8.8.8.8 등)로 가는 DNS 도 잡기 위해 /32 경로를 추가합니다.
- 업스트림 소켓은 `VpnService.protect()` 로 보호해 터널 재진입을 막습니다.
- 네트워크 변경은 `registerDefaultNetworkCallback` 으로 감지해 업스트림을 다시 만듭니다.

## 악성코드 검사 흐름

```
검사 요청 → 대상 수집(설치 앱 / SAF 로 고른 APK)
  → SHA-256 계산 → threat_hashes 대조 (일치 시 CRITICAL 확정 근거)
  → APK 정적 분석 (매니페스트/권한/컴포넌트/서명/DEX·SO 패턴)
  → 권한 조합 분석(오탐 완화 규칙 포함)
  → RiskAssessor: DANGER / WARNING / NOT_FOUND / UNABLE
  → scan_sessions / scan_results / scan_findings 저장
```

## 데이터베이스(16 테이블)

`scan_sessions`, `scan_results`, `scan_findings`, `installed_apps`, `threat_hashes`,
`threat_rules`, `threat_sources`, `threat_db_versions`, `ad_filter_rules`, `ad_filter_sources`,
`blocked_dns_events`, `allowed_domains`, `blocked_domains`, `vpn_sessions`, `update_history`,
`security_settings`

### 마이그레이션

| 버전 | 변경 |
| --- | --- |
| 1 | 초기 16 테이블 |
| 2 | `ad_filter_sources.etag`(조건부 업데이트), `update_history.httpStatus` 추가 |

`MIGRATION_1_2` 는 컬럼만 추가하며 기존 행을 보존합니다. `app/schemas/` 에 exported schema 가
체크인되어 있고, `MigrationTest` 가 v1 스키마 DDL 로 실제 DB 를 만들어 v2 로 열어
Room 스키마 검증 + 데이터 보존을 확인합니다.

## 업데이트 무결성

1. `manifest.json` 다운로드(최대 256KB)
2. **Ed25519 서명 검증** — 서명 대상은 필드 순서가 고정된 canonical JSON
3. 버전 단조 증가 확인(롤백·재적용 차단)
4. 페이로드 다운로드(최대 64MB) → **SHA-256 + 크기 검증**
5. Room 트랜잭션 안에서 교체 + 버전 행 갱신(실패 시 기존 데이터 유지)
6. `update_history` 에 결과 기록

## 의존성 주입

Hilt `SingletonComponent`:
- `DatabaseModule` — Room, DAO
- `AppModule` — CoroutineScope, AppClock, Fetcher, UpdateConfiguration(BuildConfig), UpdateClient, ApkStaticAnalyzer, PatternScanner
- `@HiltWorker` — DatabaseUpdateWorker, AutoScanWorker
