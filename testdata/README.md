# 테스트 업데이트 채널

이 폴더는 EUM SECURITY PRO 의 **서명된 업데이트 경로를 실제로 검증하기 위한 테스트 데이터**입니다.
앱의 `gradle.properties` 에 아래처럼 연결되어 있습니다.

```properties
updateBaseUrl=https://raw.githubusercontent.com/sangjindl9-lab/adout/main/testdata/update
updatePublicKey=6b80f36fa38d2942de85ff15bff2c62704c9fc9a4c1174a2dd5b8e1cd91f4326
```

- 매니페스트는 Ed25519 로 서명되어 있고, 페이로드는 SHA-256 으로 검증됩니다.
- 모든 매니페스트는 `isTestData: true` 이므로 앱 UI 에 **"예시 데이터"** 배지가 표시됩니다.
- `ShippedUpdateChannelTest` 가 이 파일들의 서명·해시·레코드 수를 실제로 검증합니다.

## 주의

- 이 키 쌍은 **테스트 전용**입니다. 개인키는 저장소에 없습니다.
- 운영 배포 시 `updateBaseUrl`/`updatePublicKey` 를 운영 채널로 교체하고, 이 폴더는
  테스트용임을 유지하거나 제거하세요.
- 데이터 파일은 절대 서명 없이 수정하면 안 됩니다(앱이 거부합니다).
