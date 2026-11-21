# EUM SECURITY PRO — ProGuard 규칙
# 실행 코드가 리플렉션/직렬화로 접근하는 항목을 보존한다.

-keepattributes *Annotation*, Signature, InnerClasses, EnclosingMethod

# Room
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-dontwarn androidx.room.paging.**

# Hilt / Dagger
-keep class dagger.hilt.** { *; }
-keep class javax.inject.** { *; }
-keep class * extends dagger.hilt.android.internal.managers.ViewComponentManager$FragmentContextWrapper

# Ed25519 (net.i2p.crypto) — JCA 프로바이더 등록을 리플렉션으로 찾는다
-keep class net.i2p.crypto.eddsa.** { *; }
-dontwarn net.i2p.crypto.eddsa.**

# 앱이 사용하는 직렬화 모델
-keep class kr.eumsoft.securitypro.data.updater.** { *; }

# WorkManager
-keep class * extends androidx.work.ListenableWorker { <init>(...); }
