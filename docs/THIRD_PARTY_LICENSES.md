# 오픈소스 라이선스 (THIRD PARTY LICENSES)

EUM SECURITY PRO 는 아래 오픈소스를 사용합니다. 각 라이선스 조건을 준수합니다.

## 1. AndroidX / Jetpack (Apache License 2.0)

- androidx.core:core-ktx, androidx.activity:activity-compose
- androidx.lifecycle:lifecycle-runtime-ktx, lifecycle-runtime-compose, lifecycle-viewmodel-compose
- androidx.navigation:navigation-compose
- androidx.room:room-runtime, room-ktx, room-testing
- androidx.datastore:datastore-preferences
- androidx.work:work-runtime-ktx
- androidx.hilt:hilt-navigation-compose, hilt-work

```
Copyright (C) The Android Open Source Project
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
```

## 2. Jetpack Compose / Material 3 (Apache License 2.0)

Copyright (C) The Android Open Source Project — Apache License 2.0 (위와 동일 전문).

## 3. Kotlin, kotlinx.coroutines (Apache License 2.0)

Copyright 2010-2024 JetBrains s.r.o. and Kotlin Programming Language contributors.
Apache License 2.0 (위와 동일 전문).

## 4. Dagger / Hilt (Apache License 2.0)

Copyright 2012 The Dagger Authors. Apache License 2.0.

## 5. eddsa (net.i2p.crypto:eddsa 0.3.0) — CC0 1.0

```
eddsa - Ed25519 implementation for Java
Copyright (c) 2015-2016 str4d
Copyright (c) 2013 The i2p Project

To the extent possible under law, the author(s) have dedicated all copyright
and related neighboring rights to this software to the public domain worldwide.
This software is distributed without any warranty.
http://creativecommons.org/publicdomain/zero/1.0/
```

Ed25519 서명 검증에만 사용합니다(업데이트 매니페스트).

## 6. StevenBlack/hosts — MIT License

기본 광고·추적 차단 목록(`app/src/main/assets/filters/stevenblack_adhoc.txt`, 원본
`data/StevenBlack/hosts` 에서 도메인만 추출).

```
The MIT License (MIT)

Copyright © 2026 Steven Black

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

> 참고: StevenBlack/hosts 의 "통합(unified)" 목록은 여러 하위 목록을 병합하며 하위 목록마다
> 라이선스가 다릅니다(예: AdAway — CC BY 3.0). 본 앱은 재배포 조건이 명확한 **MIT 단일
> 소스(`data/StevenBlack/hosts`)만** 포함합니다.

## 7. Robolectric / JUnit (테스트 전용, 앱에 포함되지 않음)

- Robolectric — MIT License
- JUnit 4 — Eclipse Public License 1.0
- org.json (JVM 테스트용) — JSON License

이들은 `testImplementation` 으로만 사용되며 APK/AAB 산출물에 포함되지 않습니다.

## 8. 포함하지 않은 라이브러리

| 라이브러리 | 이유 |
| --- | --- |
| AdGuard DNSLib (C++/Rust) | Android NDK 크로스 컴파일·JNI 안정성 검증을 이번 빌드에서 완료하지 못했습니다. 대신 순수 Kotlin DNS 엔진을 구현했습니다. |
| YARA-X (Rust, BSD-3-Clause) | Rust/NDK 크로스 컴파일 검증 미완료. 자체 YARA 부분집합 엔진으로 대체했습니다. |
| Androguard / ClamAV | 서버 분석 모듈로만 계획되어 있으며 이 버전에 포함되지 않았습니다. |
