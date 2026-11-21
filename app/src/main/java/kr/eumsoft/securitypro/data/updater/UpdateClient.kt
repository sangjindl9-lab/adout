package kr.eumsoft.securitypro.data.updater

import androidx.room.withTransaction
import kr.eumsoft.securitypro.core.crypto.Sha256
import kr.eumsoft.securitypro.data.db.AppDatabase
import kr.eumsoft.securitypro.data.db.entity.AdFilterSourceEntity
import kr.eumsoft.securitypro.data.db.entity.ThreatDbVersionEntity
import kr.eumsoft.securitypro.data.db.entity.UpdateHistoryEntity

/** 업데이트 서버/공개키 설정. */
data class UpdateConfiguration(
    val baseUrl: String,
    val publicKeyHex: String,
) {
    val isConfigured: Boolean get() = baseUrl.isNotBlank() && publicKeyHex.isNotBlank()
}

class AppClock {
    fun now(): Long = System.currentTimeMillis()
}

/**
 * 서명된 규칙/위협 DB 자동 업데이트.
 *
 * 순서: 매니페스트(Ed25519) → 페이로드(SHA-256) → 롤백 차단 → 원자적 DB 교체 → 이력 기록.
 * 어느 단계에서 실패해도 기존 데이터는 그대로 유지된다(Room 트랜잭션).
 */
class UpdateClient(
    private val db: AppDatabase,
    private val fetcher: Fetcher,
    private val configuration: UpdateConfiguration,
    private val clock: AppClock = AppClock(),
) {

    private val verifier = UpdateVerifier(configuration.publicKeyHex)

    companion object {
        const val MANIFEST_MAX_BYTES = 256L * 1024
        const val PAYLOAD_MAX_BYTES = 64L * 1024 * 1024
    }

    suspend fun updateAll(): List<UpdateOutcome> =
        UpdateTarget.entries.map { update(it) }

    suspend fun update(target: UpdateTarget): UpdateOutcome {
        val startedAt = clock.now()
        val historyId = try {
            db.updateHistoryDao().insert(
                UpdateHistoryEntity(
                    targetType = target.dbType,
                    startedAt = startedAt,
                    status = "RUNNING",
                )
            )
        } catch (_: Exception) {
            -1L
        }

        var bytes = 0L
        var sha256: String? = null
        var signatureOk = false
        var httpStatus: Int? = null
        var outcome: UpdateOutcome

        try {
            val base = configuration.baseUrl.trim().trimEnd('/')
            if (base.isEmpty() || !verifier.isConfigured()) {
                outcome = UpdateOutcome.NotConfigured(
                    target,
                    "업데이트 서버 또는 공개키가 설정되지 않았습니다.",
                )
                finish(historyId, outcome, bytes, sha256, signatureOk, startedAt, httpStatus)
                return outcome
            }

            val manifestUrl = "$base/${target.pathSegment}/manifest.json"
            val manifestResponse = fetcher.get(manifestUrl, MANIFEST_MAX_BYTES)
            httpStatus = manifestResponse.code
            if (manifestResponse.code !in 200..299) {
                outcome = UpdateOutcome.Failed(target, "매니페스트 HTTP ${manifestResponse.code}", manifestResponse.code)
                finish(historyId, outcome, bytes, sha256, signatureOk, startedAt, httpStatus)
                return outcome
            }
            val manifest = verifier.verifyManifest(String(manifestResponse.body, Charsets.UTF_8))
            signatureOk = true
            if (manifest.target != target) {
                throw UpdateRejection(
                    UpdateErrorCode.MALFORMED,
                    "매니페스트 대상 불일치: ${manifest.target} != $target",
                )
            }

            val currentVersion = db.threatDao().currentVersionNumber(target.dbType)
            verifier.checkRollback(currentVersion, manifest.version)

            val etag = if (target == UpdateTarget.AD_FILTER) currentFilterEtag() else null
            val payloadResponse = fetcher.get(manifest.payloadUrl, PAYLOAD_MAX_BYTES, etag)
            httpStatus = payloadResponse.code
            if (payloadResponse.code == 304) {
                outcome = UpdateOutcome.UpToDate(target, currentVersion)
                finish(historyId, outcome, bytes, sha256, signatureOk, startedAt, httpStatus)
                return outcome
            }
            if (payloadResponse.code !in 200..299) {
                outcome = UpdateOutcome.Failed(target, "페이로드 HTTP ${payloadResponse.code}", payloadResponse.code)
                finish(historyId, outcome, bytes, sha256, signatureOk, startedAt, httpStatus)
                return outcome
            }
            val rawPayload = payloadResponse.body
            bytes = rawPayload.size.toLong()
            verifier.verifyPayload(rawPayload, manifest)
            sha256 = Sha256.of(rawPayload)

            val payload = UpdatePayloadParser.maybeGunzip(rawPayload)
            val parsedCount = applyPayload(target, manifest, payload, payloadResponse.etag)

            if (manifest.entryCount > 0 && parsedCount != manifest.entryCount) {
                throw UpdateRejection(
                    UpdateErrorCode.MALFORMED,
                    "레코드 수 불일치: 파싱 $parsedCount != 매니페스트 ${manifest.entryCount}",
                )
            }

            outcome = UpdateOutcome.Success(
                target = target,
                version = manifest.version,
                versionLabel = manifest.versionLabel,
                records = parsedCount,
                isTestData = manifest.isTestData,
                signatureVerified = true,
            )
            finish(historyId, outcome, bytes, sha256, signatureOk, startedAt, httpStatus)
            return outcome
        } catch (rejection: UpdateRejection) {
            outcome = UpdateOutcome.Rejected(target, rejection.code, rejection.detail)
            if (rejection.code == UpdateErrorCode.NOT_CONFIGURED) signatureOk = false
            finish(historyId, outcome, bytes, sha256, signatureOk, startedAt, httpStatus)
            return outcome
        } catch (e: Exception) {
            outcome = UpdateOutcome.Failed(target, e.javaClass.simpleName + ": " + (e.message ?: "오류"), httpStatus)
            finish(historyId, outcome, bytes, sha256, signatureOk, startedAt, httpStatus)
            return outcome
        }
    }

    /** 트랜잭션 안에서 데이터 교체 + 버전 갱신. 파싱 실패 시 아무것도 바뀌지 않는다. */
    private suspend fun applyPayload(
        target: UpdateTarget,
        manifest: UpdateManifest,
        payload: ByteArray,
        etag: String?,
    ): Int {
        val json = String(payload, Charsets.UTF_8)
        var count = 0
        db.withTransaction {
            val current = db.threatDao().currentVersionNumber(target.dbType)
            verifier.checkRollback(current, manifest.version)
            when (target) {
                UpdateTarget.THREAT_HASH -> {
                    val hashes = UpdatePayloadParser.parseHashes(json)
                    if (hashes.isEmpty()) throw UpdateRejection(UpdateErrorCode.MALFORMED, "해시가 비어 있습니다.")
                    db.threatDao().replaceAllHashes(hashes)
                    count = hashes.size
                }
                UpdateTarget.YARA_RULES -> {
                    val rules = UpdatePayloadParser.parseRules(json)
                    if (rules.isEmpty()) throw UpdateRejection(UpdateErrorCode.MALFORMED, "규칙이 비어 있습니다.")
                    db.threatDao().replaceRulesForEngine("YARA_SUBSET", rules)
                    count = rules.size
                }
                UpdateTarget.AD_FILTER -> {
                    val sourceNameHint = runCatching {
                        org.json.JSONObject(json).optString("source", "update")
                    }.getOrDefault("update")
                    val sourceId = resolveFilterSource(sourceNameHint, manifest.payloadUrl, json)
                    val (entities, _, stats) =
                        UpdatePayloadParser.parseFilterRules(json, sourceId)
                    if (stats.parsed == 0) {
                        throw UpdateRejection(UpdateErrorCode.MALFORMED, "유효한 필터 규칙이 없습니다.")
                    }
                    db.adFilterDao().replaceRulesForSource(sourceId, entities)
                    count = stats.parsed
                    val sources = db.adFilterDao().sourcesOnce().filter { it.id == sourceId }
                    if (sources.isNotEmpty()) {
                        db.adFilterDao().upsertSources(
                            listOf(
                                sources.first().copy(
                                    ruleCount = stats.parsed,
                                    lastUpdatedAt = clock.now(),
                                    lastUpdateStatus = "SUCCESS",
                                    etag = etag,
                                )
                            )
                        )
                    }
                }
            }
            db.threatDao().upsertDbVersion(
                ThreatDbVersionEntity(
                    dbType = target.dbType,
                    version = manifest.version,
                    versionLabel = manifest.versionLabel,
                    recordCount = count,
                    publishedAt = manifest.publishedAt,
                    installedAt = clock.now(),
                    sha256 = manifest.payloadSha256,
                    signatureStatus = "VERIFIED",
                    isTestData = manifest.isTestData,
                )
            )
        }
        return count
    }

    private suspend fun resolveFilterSource(name: String, url: String, json: String): Long {
        db.adFilterDao().sourceIdByName(name)?.let { return it }
        val category = runCatching {
            org.json.JSONObject(json).optString("category", "ADS")
        }.getOrDefault("ADS")
        val license = runCatching {
            org.json.JSONObject(json).optString("license", "업데이트 데이터")
        }.getOrDefault("업데이트 데이터")
        val ids = db.adFilterDao().upsertSources(
            listOf(
                AdFilterSourceEntity(
                    name = name,
                    url = url,
                    license = license,
                    category = category,
                    isBuiltin = false,
                    lastUpdateStatus = "NEVER",
                )
            )
        )
        return ids.firstOrNull()
            ?: db.adFilterDao().sourceIdByName(name)
            ?: throw UpdateRejection(UpdateErrorCode.IO, "필터 소스를 만들 수 없습니다: $name")
    }

    private suspend fun currentFilterEtag(): String? {
        val sources = db.adFilterDao().sourcesOnce()
        return sources.firstOrNull { it.isBuiltin }?.etag
    }

    private suspend fun finish(
        historyId: Long,
        outcome: UpdateOutcome,
        bytes: Long,
        sha256: String?,
        signatureOk: Boolean,
        startedAt: Long,
        httpStatus: Int?,
    ) {
        if (historyId < 0) return
        val status = when (outcome) {
            is UpdateOutcome.Success -> "SUCCESS"
            is UpdateOutcome.UpToDate -> "UP_TO_DATE"
            is UpdateOutcome.NotConfigured -> "NOT_CONFIGURED"
            is UpdateOutcome.Rejected -> when (outcome.code) {
                UpdateErrorCode.ROLLBACK -> "REJECTED_ROLLBACK"
                UpdateErrorCode.SIGNATURE, UpdateErrorCode.SHA256 -> "REJECTED_INTEGRITY"
                else -> "FAILED"
            }
            is UpdateOutcome.Failed -> "FAILED"
        }
        val message = when (outcome) {
            is UpdateOutcome.Success -> "적용 완료: ${outcome.records}건"
            is UpdateOutcome.UpToDate -> "이미 최신 버전입니다."
            is UpdateOutcome.NotConfigured -> outcome.detail
            is UpdateOutcome.Rejected -> "${outcome.code}: ${outcome.detail}"
            is UpdateOutcome.Failed -> outcome.detail
        }
        val toVersion = when (outcome) {
            is UpdateOutcome.Success -> outcome.version
            else -> 0
        }
        try {
            db.updateHistoryDao().finish(
                id = historyId,
                status = status,
                toVersion = toVersion,
                finishedAt = clock.now(),
                message = message,
                signatureOk = signatureOk,
                sha256 = sha256,
                bytes = bytes,
                httpStatus = httpStatus,
            )
        } catch (_: Exception) {
            // 이력 기록 실패는 업데이트 결과를 뒤집지 않는다.
        }
    }
}
