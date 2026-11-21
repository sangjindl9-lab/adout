package kr.eumsoft.securitypro.data.db

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * 스키마 1 → 2 마이그레이션.
 *
 * 추가된 기능:
 *  - `ad_filter_sources.etag` : HTTPS 조건부 요청(If-None-Match)용
 *  - `update_history.httpStatus` : 업데이트 응답 코드 기록
 *
 * 기존 데이터를 보존하며 컬럼만 추가한다(테이블 재작성 없음).
 */
val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE ad_filter_sources ADD COLUMN etag TEXT")
        db.execSQL("ALTER TABLE update_history ADD COLUMN httpStatus INTEGER")
    }
}

val ALL_MIGRATIONS: Array<Migration> = arrayOf(MIGRATION_1_2)
