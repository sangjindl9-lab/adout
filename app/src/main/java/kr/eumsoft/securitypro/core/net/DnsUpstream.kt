package kr.eumsoft.securitypro.core.net

/**
 * DNS 업스트림(일반 UDP / DoH / DoT) 추상화.
 *
 * 구현은 Android 의 보호된 소켓(VpnService.protect)을 사용하지만, 단위 테스트에서는
 * 가짜 구현으로 대체할 수 있도록 인터페이스만 의존한다.
 */
interface DnsUpstream {
    /** 원본 DNS 질의 바이트를 업스트림으로 보내 응답 바이트를 돌려준다. 실패하면 null. */
    suspend fun resolve(query: ByteArray): ByteArray?

    /** 상태 표시용 이름(예: "Cloudflare DoH"). */
    val description: String

    fun close() {}
}
