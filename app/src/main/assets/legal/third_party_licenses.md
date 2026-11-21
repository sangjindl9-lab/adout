// EUM SECURITY PRO — 오픈소스 라이선스 고지 (앱 내 표시용)

EUM SECURITY PRO 는 아래 오픈소스를 사용합니다. 각 라이선스 전문은 저장소의
docs/THIRD_PARTY_LICENSES.md 에 있습니다.

1. AndroidX / Jetpack (Apache-2.0)
   - core-ktx, activity-compose, lifecycle, navigation-compose, room, datastore,
     work-runtime-ktx, hilt-navigation-compose, hilt-work

2. Jetpack Compose / Material 3 (Apache-2.0)

3. Kotlin, Kotlin Coroutines (Apache-2.0)

4. Dagger Hilt (Apache-2.0)

5. eddsa (net.i2p.crypto:eddsa) — CC0 1.0 / MIT (프로젝트 표기 기준)
   Ed25519 서명 검증에 사용합니다.

6. StevenBlack/hosts — MIT License
   Copyright (c) 2026 Steven Black
   기본 광고·추적 차단 목록(assets/filters/stevenblack_adhoc.txt)

7. Android Open Source Project (Apache-2.0) — 플랫폼 API

YARA-X(VirusTotal, BSD-3-Clause)는 네이티브 크로스 컴파일이 검증되지 않아 포함되지
않았습니다. 대신 자체 작성한 YARA 부분집합 엔진(core/yara)이 사용됩니다.
