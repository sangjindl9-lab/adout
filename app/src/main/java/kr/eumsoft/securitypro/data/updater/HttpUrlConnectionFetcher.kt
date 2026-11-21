package kr.eumsoft.securitypro.data.updater

import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** HttpURLConnection 기반 HTTPS 다운로드. 리다이렉트는 https 만 허용한다. */
class HttpUrlConnectionFetcher(
    private val userAgent: String = "EUM-SECURITY-PRO/1.0 (Android)",
    private val connectTimeoutMs: Int = 15_000,
    private val readTimeoutMs: Int = 30_000,
) : Fetcher {

    override suspend fun get(url: String, maxBytes: Long, etag: String?): Fetcher.Response =
        withContext(Dispatchers.IO) {
            if (!url.startsWith("https://")) {
                throw UpdateRejection(UpdateErrorCode.MALFORMED, "HTTPS 가 아닌 URL: $url")
            }
            var current = url
            var redirects = 0
            while (true) {
                val connection = (URL(current).openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    setRequestProperty("User-Agent", userAgent)
                    setRequestProperty("Accept-Encoding", "identity")
                    if (etag != null) setRequestProperty("If-None-Match", etag)
                    connectTimeout = connectTimeoutMs
                    readTimeout = readTimeoutMs
                    instanceFollowRedirects = false
                }
                try {
                    val code = try {
                        connection.responseCode
                    } catch (e: IOException) {
                        throw UpdateRejection(UpdateErrorCode.IO, "연결 실패: ${e.message}")
                    }
                    if (code in 300..399) {
                        val location = connection.getHeaderField("Location")
                        if (location.isNullOrBlank() || redirects >= 3) {
                            throw UpdateRejection(UpdateErrorCode.HTTP, "리다이렉트 처리 실패($code)")
                        }
                        val next = if (location.startsWith("http")) location else URL(URL(current), location).toString()
                        if (!next.startsWith("https://")) {
                            throw UpdateRejection(UpdateErrorCode.HTTP, "HTTPS 가 아닌 리다이렉트 차단")
                        }
                        current = next
                        redirects++
                        continue
                    }
                    if (code == 304) {
                        return@withContext Fetcher.Response(304, ByteArray(0), etag)
                    }
                    if (code !in 200..299) {
                        return@withContext Fetcher.Response(code, ByteArray(0))
                    }
                    val declared = connection.contentLengthLong
                    if (declared > maxBytes) {
                        throw UpdateRejection(UpdateErrorCode.TOO_LARGE, "Content-Length 초과: $declared > $maxBytes")
                    }
                    val body = connection.inputStream.use { input ->
                        readLimited(input, maxBytes)
                    }
                    return@withContext Fetcher.Response(
                        code = code,
                        body = body,
                        etag = connection.getHeaderField("ETag"),
                        contentType = connection.contentType,
                    )
                } finally {
                    connection.disconnect()
                }
            }
            @Suppress("UNREACHABLE_CODE")
            throw UpdateRejection(UpdateErrorCode.UNKNOWN, "도달할 수 없는 상태")
        }

    private fun readLimited(input: java.io.InputStream, maxBytes: Long): ByteArray {
        val out = java.io.ByteArrayOutputStream(8192)
        val buffer = ByteArray(32 * 1024)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) break
            total += read
            if (total > maxBytes) {
                throw UpdateRejection(UpdateErrorCode.TOO_LARGE, "다운로드 크기 초과: $total > $maxBytes")
            }
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }

    companion object {
        /** file:// 은 테스트/로컬 배포용으로만 허용(운영 경로에서는 사용하지 않는다). */
        fun readLocal(file: File, maxBytes: Long): ByteArray {
            if (!file.isFile) throw UpdateRejection(UpdateErrorCode.IO, "파일 없음: ${file.path}")
            if (file.length() > maxBytes) throw UpdateRejection(UpdateErrorCode.TOO_LARGE, "파일 크기 초과")
            return file.readBytes()
        }
    }
}
