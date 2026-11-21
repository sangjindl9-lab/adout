package kr.eumsoft.securitypro.data.db

import androidx.room.Embedded
import androidx.room.Relation
import kr.eumsoft.securitypro.data.db.entity.ScanFindingEntity
import kr.eumsoft.securitypro.data.db.entity.ScanResultEntity
import kr.eumsoft.securitypro.data.db.entity.ScanSessionEntity

/** 검사 세션 + 결과 + 근거 전체 묶음(검사 결과 화면용). */
data class ScanSessionDetail(
    @Embedded val session: ScanSessionEntity,
    @Relation(entity = ScanResultEntity::class, parentColumn = "id", entityColumn = "sessionId")
    val results: List<ScanResultWithFindings>,
)

/** 검사 대상 1건 + 근거 목록. */
data class ScanResultWithFindings(
    @Embedded val result: ScanResultEntity,
    @Relation(entity = ScanFindingEntity::class, parentColumn = "id", entityColumn = "resultId")
    val findings: List<ScanFindingEntity>,
)

/** 시간대별 차단 건수 집계. */
data class HourBucket(
    val hourStart: Long,
    val count: Int,
)

/** 범주별 차단 건수 집계. */
data class CategoryCount(
    val category: String,
    val count: Int,
)

/** 일별 차단 건수 집계. */
data class DayBucket(
    val dayStart: Long,
    val count: Int,
)
