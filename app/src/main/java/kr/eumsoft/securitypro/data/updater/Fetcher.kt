package kr.eumsoft.securitypro.data.updater

/**
 * HTTPS 다운로드 추상화. 단위 테스트에서는 로컬 HTTP 서버나 가짜 구현으로 대체한다.
 */
interface Fetcher {
    data class Response(
        val code: Int,
        val body: ByteArray,
        val etag: String? = null,
        val contentType: String? = null,
    )

    /** 최대 [maxBytes] 까지만 읽는다. 초과 시 [UpdateRejection](TOO_LARGE). */
    suspend fun get(url: String, maxBytes: Long, etag: String? = null): Response
}
