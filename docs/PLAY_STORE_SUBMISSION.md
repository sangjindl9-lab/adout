# Google Play 등록 자료 (초안)

## 1. 스토어 리스팅

**앱 이름**: EUM SECURITY PRO — 광고 차단 & 악성코드 검사

**짧은 설명 (80자)**
- KO: 광고·추적 DNS 차단과 APK 악성코드 검사를 한 앱에서. 데이터는 기기에만 저장됩니다.
- EN: Block ad/tracker DNS and scan APKs for malware in one app. Data stays on your device.

**전체 설명 (KO)**

> EUM SECURITY PRO 는 광고·추적 도메인을 DNS 수준에서 차단하고, 설치된 앱과 APK 파일의
> 악성코드 흔적을 기기 안에서 검사하는 통합 보안 앱입니다.
>
> · 광고 차단: 로컬 VPN 으로 DNS 질의만 필터링합니다. 일반 인터넷 트래픽은 VPN 을 지나지 않습니다.
> · 추적/피싱/악성 도메인 차단: 필터 목록을 켜고 끌 수 있고, 특정 사이트를 허용/차단할 수 있습니다.
> · 악성코드 검사: SHA-256 해시 대조, APK 정적 분석(권한·컴포넌트·서명·DEX 패턴), 위험 권한 조합 분석.
> · 결과는 '위험 / 주의 / 알려진 위협 미발견 / 검사 불가' 4단계로 표시하고 근거와 권장 조치를 함께 보여줍니다.
> · DNS 기록과 검사 결과는 기기 밖으로 전송되지 않습니다.
>
> * DNS 방식은 앱 내부 광고나 HTTPS 영상 광고를 제거하지 못합니다.
> * 어떤 앱도 "100% 안전"을 보장할 수 없으며, 이 앱은 알려진 위협 정보와 휴리스틱 근거를 제공합니다.

**카테고리**: 도구(Tools) / 보안

**필요 이미지 자료**
- 앱 아이콘 512×512 PNG
- 대표 이미지 1024×500 PNG
- 스마트폰 스크린샷 2~8장 (홈/광고 차단/검사 진행/검사 결과/보안 DB/설정)
- 태블릿 스크린샷 (10인치, 선택)

## 2. VPN 사용 목적 신고 (Play Console → 앱 콘텐츠 → VPN)

> EUM SECURITY PRO uses the Android VpnService to filter DNS queries on the device. The VPN
> only routes DNS traffic to a local virtual DNS server (10.111.222.2) where requests are
> checked against ad, tracker, phishing and malware domain lists. Traffic other than DNS is
> not routed through the VPN. No traffic is decrypted, no content is inspected, and DNS logs
> never leave the device. The VPN is started and stopped by the user and is never restarted
> automatically after the user stops it. The foreground service notification explains the
> active state at all times.

한국어 요약: 로컬 VPN 은 DNS 질의만 로컬 가상 DNS 서버로 보내 광고·추적·피싱·악성 도메인
목록과 대조합니다. DNS 이외 트래픽은 라우팅하지 않고, 복호화·내용 검사·외부 전송이 없습니다.

## 3. QUERY_ALL_PACKAGES 사용 목적 신고

> EUM SECURITY PRO declares QUERY_ALL_PACKAGES because its core function is scanning installed
> applications for malware. The app reads package metadata (label, version, installer, requested
> permissions, signing certificate SHA-256) and, when readable, the APK file itself to compute a
> SHA-256 hash and perform static analysis (manifest, components, DEX/native patterns). No app
> list or file content is uploaded; results are stored only in the on-device database. Users can
> delete all results at any time in Settings.

한국어 요약: 설치 앱 악성코드 검사가 핵심 기능이므로 전체 앱 조회 권한이 필요합니다.
수집한 정보는 기기 내부에만 저장되고 외부로 전송되지 않습니다.

## 4. 데이터 보안(Data safety) 신고 요약

| 항목 | 신고 |
| --- | --- |
| 데이터 수집 | 없음(서버 전송 없음) |
| 데이터 공유 | 없음 |
| 전송 중 암호화 | 해당 없음(수집 없음). 업데이트/DoH 는 HTTPS/TLS 사용 |
| 삭제 요청 | 앱 내 "검사·차단 기록 삭제" 로 즉시 삭제 |
| 광고 | 없음 |
| 위치/연락처/금융 정보 | 접근하지 않음(검사 대상 앱의 권한 목록만 읽음) |

## 5. 심사 시 참고 사항

- VPN 동의 화면은 Android 표준 `VpnService.prepare()` 를 사용합니다.
- 포그라운드 서비스는 `specialUse` + `PROPERTY_SPECIAL_USE_FGS_SUBTYPE=dns_ad_and_tracker_blocking_vpn` 로 선언했습니다.
- 악성코드 검사 결과에는 항상 근거가 표시되며, "100% 안전" 같은 표현을 사용하지 않습니다.
- 오탐 신고 경로(메일 템폴릿)와 권장 조치(앱 정보/삭제 화면)를 제공합니다.

## 6. 테스트 계정/절차

- 로그인 없이 동작합니다.
- VPN 테스트: 앱 실행 → 광고 차단 화면 → "VPN 켜기" → 시스템 동의 → 브라우저에서
  `https://doubleclick.net` 접속 시 차단 통계 증가 확인.
- 악성코드 검사: "빠른 검사" 실행 → 결과 화면에서 엔진/근거/미검사 항목 확인.
