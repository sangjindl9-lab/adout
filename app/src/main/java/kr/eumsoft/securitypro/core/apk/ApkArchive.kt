package kr.eumsoft.securitypro.core.apk

import java.io.File
import java.util.zip.ZipInputStream

/** ZIP 압축 폭탄/과대 엔트리를 방어하기 위한 한도. */
data class ArchiveLimits(
    val maxEntries: Int = 200_000,
    val maxEntryBytes: Long = 64L * 1024 * 1024,
    val maxTotalBytes: Long = 512L * 1024 * 1024,
    /** 이 크기 이상 풀렸을 때 압축비가 [maxRatio] 를 넘으면 폭탄으로 본다. */
    val ratioCheckBytes: Long = 1L * 1024 * 1024,
    val maxRatio: Int = 200,
)

class ArchiveLimitException(message: String) : Exception(message)

/** 읽은 압축 바이트 수를 세는 스트림(압축비 계산용). */
internal class CountingInputStream(
    private val delegate: java.io.InputStream,
) : java.io.FilterInputStream(delegate) {
    @Volatile
    var count: Long = 0L
        private set

    override fun read(): Int {
        val value = super.read()
        if (value >= 0) count++
        return value
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        val read = super.read(b, off, len)
        if (read > 0) count += read
        return read
    }

    override fun skip(n: Long): Long {
        val skipped = super.skip(n)
        if (skipped > 0) count += skipped
        return skipped
    }
}

data class ArchiveReadStats(
    val entries: Int,
    val totalBytes: Long,
    val skippedLargeEntries: Int,
    val bombSuspected: Boolean,
    val truncated: Boolean,
)

/**
 * APK(ZIP) 를 스트리밍으로 안전하게 읽는다.
 *
 * - 엔트리 수/개별 크기/전체 크기 상한
 * - 압축비 검사(압축 폭탄)
 * - 손상된 ZIP 은 예외 대신 결과 플래그로 보고
 */
object ApkArchive {

    /**
     * @param select 엔트리를 바이트로 읽을지 결정한다(파일명, 선언 크기).
     * @param onEntry 선택된 엔트리의 바이트.
     */
    fun read(
        file: File,
        limits: ArchiveLimits = ArchiveLimits(),
        select: (String, Long) -> Boolean,
        onEntry: (String, ByteArray) -> Unit,
    ): ArchiveReadStats {
        var entries = 0
        var totalBytes = 0L
        var skippedLarge = 0
        var bomb = false
        var truncated = false

        file.inputStream().use { raw ->
            val counter = CountingInputStream(raw)
            ZipInputStream(counter).use { zip ->
                while (true) {
                    val entry = try {
                        zip.nextEntry ?: break
                    } catch (_: Exception) {
                        truncated = true
                        break
                    }
                    entries++
                    if (entries > limits.maxEntries) {
                        bomb = true
                        break
                    }
                    val declared = entry.size
                    if (entry.isDirectory) continue
                    val name = entry.name
                    if (!select(name, declared)) {
                        runCatching { zip.closeEntry() }
                        continue
                    }
                    val out = java.io.ByteArrayOutputStream(
                        if (declared in 1..(8L * 1024 * 1024)) declared.toInt() else 64 * 1024
                    )
                    val buffer = ByteArray(64 * 1024)
                    var entryBytes = 0L
                    val compressedBefore = counter.count
                    var ok = true
                    while (true) {
                        val read = try {
                            zip.read(buffer)
                        } catch (_: Exception) {
                            truncated = true
                            ok = false
                            break
                        }
                        if (read <= 0) break
                        entryBytes += read
                        totalBytes += read
                        if (entryBytes > limits.maxEntryBytes || totalBytes > limits.maxTotalBytes) {
                            skippedLarge++
                            ok = false
                            break
                        }
                        if (entryBytes >= limits.ratioCheckBytes) {
                            val compressed = (counter.count - compressedBefore).coerceAtLeast(1)
                            if (entryBytes / compressed > limits.maxRatio) {
                                bomb = true
                                ok = false
                                break
                            }
                        }
                        out.write(buffer, 0, read)
                    }
                    if (ok) {
                        onEntry(name, out.toByteArray())
                    } else if (bomb) {
                        break
                    }
                    runCatching { zip.closeEntry() }
                }
            }
        }
        return ArchiveReadStats(
            entries = entries,
            totalBytes = totalBytes,
            skippedLargeEntries = skippedLarge,
            bombSuspected = bomb,
            truncated = truncated,
        )
    }

    /** ZIP 중앙 디렉터리를 신뢰하지 않고 엔트리 이름만 빠르게 훑는다. */
    fun entryNames(file: File, limits: ArchiveLimits = ArchiveLimits()): List<String> {
        val names = ArrayList<String>()
        file.inputStream().use { raw ->
            ZipInputStream(CountingInputStream(raw)).use { zip ->
                var count = 0
                while (true) {
                    val entry = try {
                        zip.nextEntry ?: break
                    } catch (_: Exception) {
                        break
                    }
                    names += entry.name
                    count++
                    if (count >= limits.maxEntries) break
                }
            }
        }
        return names
    }
}
